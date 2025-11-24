fn merkle_path_opening(
    builder: &mut R1csBuilder,
    leaf: &[Byte],
    path: &[Vec<u8>],
    position: usize,
) -> [BitWord; 8] {
    loquat_debug!(
        "[r1cs] merkle_path_opening depth={} position={}",
        path.len(),
        position
    );
    let mut current = sha256_hash_bytes(builder, leaf);
    let mut idx = position;
    for sibling_bytes in path {
        let sibling_byte_structs = sibling_bytes
            .iter()
            .map(|&byte| Byte::from_constant(builder, byte))
            .collect::<Vec<_>>();
        let sibling_bits = sha256_hash_bytes(builder, &sibling_byte_structs);
        let mut concat = Vec::new();
        if idx % 2 == 0 {
            concat.extend(bytes_from_bitwords(&current));
            concat.extend(bytes_from_bitwords(&sibling_bits));
        } else {
            concat.extend(bytes_from_bitwords(&sibling_bits));
            concat.extend(bytes_from_bitwords(&current));
        }
        current = sha256_hash_bytes(builder, &concat);
        idx /= 2;
    }
    current
}
use crate::loquat::encoding;
use crate::loquat::errors::{LoquatError, LoquatResult};
use crate::loquat::fft::{evaluate_on_coset, interpolate_on_coset};
use crate::loquat::field_utils::{self, field2_to_bytes, field_to_u128, F, F2};
use crate::loquat::setup::LoquatPublicParams;
use crate::loquat::sign::LoquatSignature;
use crate::loquat::sumcheck::replay_sumcheck_challenges;
use crate::loquat::transcript::Transcript;
use crate::snarks::r1cs::{R1csConstraint, R1csInstance, R1csWitness};
use sha2::{Digest, Sha256};

const LEGENDRE_EXPONENT_BITS: usize = 126;
const LEGENDRE_EXPONENT_ITERS: usize = LEGENDRE_EXPONENT_BITS - 1;
const WORD_BITS: usize = 32;
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

struct LegendreConstants {
    two: F,
    two_inv: F,
}

struct TranscriptData {
    i_indices: Vec<usize>,
    lambda_scalars: Vec<F>,
    epsilon_vals: Vec<F2>,
    sumcheck_challenges: Vec<F2>,
    z_challenge: F2,
    e_vector: Vec<F2>,
}

struct SparseLC {
    constant: F,
    terms: Vec<(usize, F)>,
}

#[derive(Clone, Copy)]
struct F2Var {
    c0: usize,
    c1: usize,
}

#[derive(Clone, Debug)]
struct BitWord {
    bits: Vec<usize>,
    value: u32,
}

#[derive(Clone, Debug)]
struct Byte {
    bits: [usize; 8],
    value: u8,
}

impl BitWord {
    fn len(&self) -> usize {
        self.bits.len()
    }

    fn bit_value(&self, index: usize) -> bool {
        ((self.value >> index) & 1) == 1
    }

    fn rotate_right(&self, amount: usize) -> Self {
        let len = self.bits.len();
        if len == 0 {
            return self.clone();
        }
        let shift = amount % len;
        let mut rotated_bits = Vec::with_capacity(len);
        for i in 0..len {
            rotated_bits.push(self.bits[(i + shift) % len]);
        }
        Self {
            bits: rotated_bits,
            value: self.value.rotate_right(shift as u32),
        }
    }

    fn shift_right(&self, amount: usize, builder: &mut R1csBuilder) -> Self {
        let len = self.bits.len();
        if amount >= len {
            let zero_bits = (0..len)
                .map(|_| builder.alloc_bit(false))
                .collect::<Vec<_>>();
            return Self {
                bits: zero_bits,
                value: 0,
            };
        }
        let mut bits = Vec::with_capacity(len);
        for _ in 0..amount {
            bits.push(builder.alloc_bit(false));
        }
        for i in amount..len {
            bits.push(self.bits[i - amount]);
        }
        Self {
            bits,
            value: self.value >> amount,
        }
    }

    fn from_constant(builder: &mut R1csBuilder, value: u32) -> Self {
        let mut bits = Vec::with_capacity(WORD_BITS);
        for i in 0..WORD_BITS {
            let bit_val = ((value >> i) & 1) == 1;
            bits.push(builder.alloc_bit(bit_val));
        }
        Self { bits, value }
    }
}

impl Byte {
    fn from_bits(bits: [usize; 8], value: u8) -> Self {
        Self { bits, value }
    }

    fn from_constant(builder: &mut R1csBuilder, value: u8) -> Self {
        let mut bits = [0usize; 8];
        for i in 0..8 {
            let bit_val = ((value >> i) & 1) == 1;
            bits[i] = builder.alloc_bit(bit_val);
        }
        Self { bits, value }
    }
}

impl SparseLC {
    fn zero() -> Self {
        Self {
            constant: F::zero(),
            terms: Vec::new(),
        }
    }

    fn constant(value: F) -> Self {
        Self {
            constant: value,
            terms: Vec::new(),
        }
    }

    fn from_var(idx: usize) -> Self {
        Self {
            constant: F::zero(),
            terms: vec![(idx, F::one())],
        }
    }

    fn with_terms(constant: F, mut terms: Vec<(usize, F)>) -> Self {
        terms.sort_by_key(|(idx, _)| *idx);
        let mut combined = Vec::with_capacity(terms.len());
        for (idx, coeff) in terms {
            if let Some((last_idx, last_coeff)) = combined.last_mut() {
                if *last_idx == idx {
                    *last_coeff += coeff;
                    continue;
                }
            }
            combined.push((idx, coeff));
        }
        Self {
            constant,
            terms: combined,
        }
    }

    fn to_dense(&self, num_variables: usize) -> Vec<F> {
        let mut dense = vec![F::zero(); num_variables];
        dense[0] = self.constant;
        for (idx, coeff) in &self.terms {
            dense[*idx] += *coeff;
        }
        dense
    }
}

struct PendingConstraint {
    a: SparseLC,
    b: SparseLC,
    c: SparseLC,
}

struct R1csBuilder {
    witness: Vec<F>,
    constraints: Vec<PendingConstraint>,
}

impl R1csBuilder {
    fn new() -> Self {
        Self {
            witness: Vec::new(),
            constraints: Vec::new(),
        }
    }

    fn alloc(&mut self, value: F) -> usize {
        self.witness.push(value);
        self.witness.len()
    }

    fn enforce_mul(&mut self, a: SparseLC, b: SparseLC, c: SparseLC) {
        self.constraints.push(PendingConstraint { a, b, c });
    }

    fn enforce_mul_const_var(&mut self, constant: F, var_idx: usize, out_idx: usize) {
        let a = SparseLC::constant(constant);
        let b = SparseLC::from_var(var_idx);
        let c = SparseLC::from_var(out_idx);
        self.enforce_mul(a, b, c);
    }

    fn enforce_mul_vars(&mut self, left_idx: usize, right_idx: usize, out_idx: usize) {
        let a = SparseLC::from_var(left_idx);
        let b = SparseLC::from_var(right_idx);
        let c = SparseLC::from_var(out_idx);
        self.enforce_mul(a, b, c);
    }

    fn enforce_sum_equals(&mut self, terms: &[(usize, F)], target_idx: usize) {
        let mut lc_terms = terms.to_vec();
        lc_terms.push((target_idx, -F::one()));
        let lc = SparseLC::with_terms(F::zero(), lc_terms);
        let one = SparseLC::constant(F::one());
        let zero = SparseLC::zero();
        self.enforce_mul(lc, one, zero);
    }

    fn enforce_linear_relation(&mut self, terms: &[(usize, F)], constant: F) {
        let lc = SparseLC::with_terms(constant, terms.to_vec());
        let one = SparseLC::constant(F::one());
        let zero = SparseLC::zero();
        self.enforce_mul(lc, one, zero);
    }

    fn enforce_eq(&mut self, left_idx: usize, right_idx: usize) {
        self.enforce_sum_equals(&[(left_idx, F::one())], right_idx);
    }

    fn enforce_boolean(&mut self, idx: usize) {
        let a = SparseLC::from_var(idx);
        let b = SparseLC::with_terms(-F::one(), vec![(idx, F::one())]);
        let c = SparseLC::zero();
        self.enforce_mul(a, b, c);
    }

    fn alloc_f2(&mut self, value: F2) -> F2Var {
        F2Var {
            c0: self.alloc(value.c0),
            c1: self.alloc(value.c1),
        }
    }

    fn enforce_f2_eq(&mut self, left: F2Var, right: F2Var) {
        self.enforce_eq(left.c0, right.c0);
        self.enforce_eq(left.c1, right.c1);
    }

    fn enforce_f2_sum_equals_unit(&mut self, vars: &[F2Var], target: F2Var) {
        let mut c0_terms = Vec::with_capacity(vars.len());
        let mut c1_terms = Vec::with_capacity(vars.len());
        for var in vars {
            c0_terms.push((var.c0, F::one()));
            c1_terms.push((var.c1, F::one()));
        }
        self.enforce_sum_equals(&c0_terms, target.c0);
        self.enforce_sum_equals(&c1_terms, target.c1);
    }

    fn enforce_f2_sub(&mut self, left: F2Var, right: F2Var, target: F2Var) {
        let real_terms = vec![
            (target.c0, F::one()),
            (left.c0, -F::one()),
            (right.c0, F::one()),
        ];
        let imag_terms = vec![
            (target.c1, F::one()),
            (left.c1, -F::one()),
            (right.c1, F::one()),
        ];
        self.enforce_linear_relation(&real_terms, F::zero());
        self.enforce_linear_relation(&imag_terms, F::zero());
    }

    fn enforce_f2_sum_equals_const(&mut self, vars: &[F2Var], constant: F2) {
        let mut c0_terms = Vec::with_capacity(vars.len());
        let mut c1_terms = Vec::with_capacity(vars.len());
        for var in vars {
            c0_terms.push((var.c0, F::one()));
            c1_terms.push((var.c1, F::one()));
        }
        let c0_idx = self.alloc(constant.c0);
        let c1_idx = self.alloc(constant.c1);
        self.enforce_sum_equals(&c0_terms, c0_idx);
        self.enforce_sum_equals(&c1_terms, c1_idx);
    }

    fn decompose_to_bits(&mut self, var_idx: usize, value: F, bit_len: usize) -> Vec<usize> {
        let mut bits = Vec::with_capacity(bit_len);
        let mut value_u128 = field_to_u128(value);
        for _ in 0..bit_len {
            let bit = (value_u128 & 1) as u128;
            value_u128 >>= 1;
            let bit_idx = self.alloc(F::new(bit));
            self.enforce_boolean(bit_idx);
            bits.push(bit_idx);
        }

        let mut terms = vec![(var_idx, F::one())];
        for (bit_position, bit_idx) in bits.iter().enumerate() {
            let coeff = -F::new(1u128 << bit_position);
            terms.push((*bit_idx, coeff));
        }
        self.enforce_linear_relation(&terms, F::zero());
        bits
    }

    fn alloc_bit(&mut self, value: bool) -> usize {
        let idx = self.alloc(F::new(value as u128));
        self.enforce_boolean(idx);
        idx
    }

    fn and_bits(
        &mut self,
        left_idx: usize,
        right_idx: usize,
        left_value: bool,
        right_value: bool,
    ) -> (usize, bool) {
        let result_value = left_value & right_value;
        let result_idx = self.alloc(F::new(result_value as u128));
        self.enforce_boolean(result_idx);
        self.enforce_mul_vars(left_idx, right_idx, result_idx);
        (result_idx, result_value)
    }

    fn xor_bits(
        &mut self,
        left_idx: usize,
        right_idx: usize,
        left_value: bool,
        right_value: bool,
    ) -> (usize, bool) {
        let result_value = left_value ^ right_value;
        let result_idx = self.alloc(F::new(result_value as u128));
        self.enforce_boolean(result_idx);

        let prod_value = left_value & right_value;
        let prod_idx = self.alloc(F::new(prod_value as u128));
        self.enforce_mul_vars(left_idx, right_idx, prod_idx);

        let two = F::new(2);
        self.enforce_linear_relation(
            &[
                (result_idx, F::one()),
                (prod_idx, two),
                (left_idx, -F::one()),
                (right_idx, -F::one()),
            ],
            F::zero(),
        );
        (result_idx, result_value)
    }

    fn xor3_bits(
        &mut self,
        a_idx: usize,
        b_idx: usize,
        c_idx: usize,
        a_val: bool,
        b_val: bool,
        c_val: bool,
    ) -> (usize, bool) {
        let (ab_idx, ab_val) = self.xor_bits(a_idx, b_idx, a_val, b_val);
        self.xor_bits(ab_idx, c_idx, ab_val, c_val)
    }

    fn not_bit(&mut self, bit_idx: usize, bit_value: bool) -> (usize, bool) {
        let result_value = !bit_value;
        let result_idx = self.alloc(F::new(result_value as u128));
        self.enforce_boolean(result_idx);
        self.enforce_linear_relation(&[(result_idx, F::one()), (bit_idx, F::one())], -F::one());
        (result_idx, result_value)
    }

    fn majority_bits(
        &mut self,
        a_idx: usize,
        b_idx: usize,
        c_idx: usize,
        a_val: bool,
        b_val: bool,
        c_val: bool,
    ) -> (usize, bool) {
        let (ab_idx, ab_val) = self.and_bits(a_idx, b_idx, a_val, b_val);
        let (ac_idx, ac_val) = self.and_bits(a_idx, c_idx, a_val, c_val);
        let (bc_idx, bc_val) = self.and_bits(b_idx, c_idx, b_val, c_val);
        let (tmp_idx, tmp_val) = self.xor_bits(ab_idx, ac_idx, ab_val, ac_val);
        self.xor_bits(tmp_idx, bc_idx, tmp_val, bc_val)
    }

    fn choice_bits(
        &mut self,
        x_idx: usize,
        y_idx: usize,
        z_idx: usize,
        x_val: bool,
        y_val: bool,
        z_val: bool,
    ) -> (usize, bool) {
        let (xy_idx, xy_val) = self.and_bits(x_idx, y_idx, x_val, y_val);
        let (not_x_idx, not_x_val) = self.not_bit(x_idx, x_val);
        let (nz_idx, nz_val) = self.and_bits(not_x_idx, z_idx, not_x_val, z_val);
        self.xor_bits(xy_idx, nz_idx, xy_val, nz_val)
    }

    fn finalize(self) -> LoquatResult<(R1csInstance, R1csWitness)> {
        let num_variables = self.witness.len() + 1;
        let constraints = self
            .constraints
            .into_iter()
            .map(|pending| {
                let a = pending.a.to_dense(num_variables);
                let b = pending.b.to_dense(num_variables);
                let c = pending.c.to_dense(num_variables);
                R1csConstraint::new(a, b, c)
            })
            .collect::<Vec<_>>();
        let instance = R1csInstance::new(num_variables, constraints)?;
        let witness = R1csWitness::new(self.witness);
        witness.validate(&instance)?;
        Ok((instance, witness))
    }
}

fn expand_challenge<T>(
    seed: &[u8],
    count: usize,
    domain_separator: &[u8],
    parser: &mut dyn FnMut(&[u8]) -> T,
) -> Vec<T> {
    let mut results = Vec::with_capacity(count);
    let mut counter: u32 = 0;
    while results.len() < count {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(domain_separator);
        hasher.update(&counter.to_le_bytes());
        let hash_output = hasher.finalize();
        results.push(parser(&hash_output));
        counter += 1;
    }
    results
}

fn replay_transcript_data(
    message: &[u8],
    signature: &LoquatSignature,
    params: &LoquatPublicParams,
) -> LoquatResult<TranscriptData> {
    let mut transcript = Transcript::new(b"loquat_signature");
    transcript.append_message(b"message", message);

    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_commitment = hasher.finalize().to_vec();
    if message_commitment != signature.message_commitment {
        return Err(LoquatError::verification_failure(
            "message commitment mismatch",
        ));
    }
    transcript.append_message(b"message_commitment", &message_commitment);

    transcript.append_message(b"root_c", &signature.root_c);
    let t_bytes = encoding::serialize_field_matrix(&signature.t_values);
    transcript.append_message(b"t_values", &t_bytes);

    let mut h1_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h1", &mut h1_bytes);
    let num_checks = params.m * params.n;
    let i_indices = expand_challenge(&h1_bytes, num_checks, b"I_indices", &mut |b| {
        (u64::from_le_bytes(b[0..8].try_into().unwrap()) as usize) % params.l
    });

    let o_bytes = encoding::serialize_field_matrix(&signature.o_values);
    transcript.append_message(b"o_values", &o_bytes);

    let mut h2_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h2", &mut h2_bytes);
    let lambda_scalars = expand_challenge(&h2_bytes, num_checks, b"lambdas", &mut |b| {
        field_utils::bytes_to_field_element(b)
    });
    let epsilon_vals = expand_challenge(&h2_bytes, params.n, b"e_j", &mut |b| {
        F2::new(field_utils::bytes_to_field_element(b), F::zero())
    });

    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    let sumcheck_challenges =
        replay_sumcheck_challenges(&signature.pi_us, num_variables, &mut transcript)?;

    transcript.append_message(b"root_s", &signature.root_s);
    let s_sum_bytes = field2_to_bytes(&signature.s_sum);
    transcript.append_message(b"s_sum", &s_sum_bytes);
    let mut h3_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h3", &mut h3_bytes);
    let z_scalar = field_utils::bytes_to_field_element(&h3_bytes);
    let z_challenge = F2::new(z_scalar, F::zero());

    transcript.append_message(b"root_h", &signature.root_h);
    let mut h4_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h4", &mut h4_bytes);
    let e_vector = expand_challenge(&h4_bytes, 8, b"e_vector", &mut |b| {
        F2::new(field_utils::bytes_to_field_element(b), F::zero())
    });

    Ok(TranscriptData {
        i_indices,
        lambda_scalars,
        epsilon_vals,
        sumcheck_challenges,
        z_challenge,
        e_vector,
    })
}

pub fn build_loquat_r1cs(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &[F],
    params: &LoquatPublicParams,
) -> LoquatResult<(R1csInstance, R1csWitness)> {
    trace_stage("build_loquat_r1cs: begin");
    if public_key.len() < params.l {
        return Err(LoquatError::verification_failure(
            "public key length below parameter l",
        ));
    }

    let transcript_data = replay_transcript_data(message, signature, params)?;
    trace_stage("transcript data replayed from artifact");
    if signature.z_challenge != transcript_data.z_challenge {
        return Err(LoquatError::verification_failure("z challenge mismatch"));
    }
    if signature.e_vector != transcript_data.e_vector {
        return Err(LoquatError::verification_failure("e-vector mismatch"));
    }
    if signature.ldt_proof.commitments.len() != params.r + 1 {
        return Err(LoquatError::verification_failure(
            "LDT commitment count mismatch",
        ));
    }
    if signature.ldt_proof.openings.len() != params.kappa {
        return Err(LoquatError::verification_failure(
            "LDT opening count mismatch",
        ));
    }
    if signature.fri_codewords.len() != params.r + 1
        || signature.fri_rows.len() != params.r + 1
        || signature.fri_challenges.len() != params.r
    {
        return Err(LoquatError::verification_failure(
            "FRI transcript length mismatch",
        ));
    }
    if signature.message_commitment.len() != 32 {
        return Err(LoquatError::verification_failure(
            "message commitment must be 32 bytes",
        ));
    }
    let mut message_commitment = [0u8; 32];
    message_commitment.copy_from_slice(&signature.message_commitment);

    let mut builder = R1csBuilder::new();
    let message_bytes = bytes_from_constants(&mut builder, message);
    let computed_commitment = sha256_hash_bytes(&mut builder, &message_bytes);
    enforce_digest_equals_bytes(&mut builder, &computed_commitment, &message_commitment);
    trace_stage("message commitment enforced inside circuit");
    let message_commitment_bytes = bytes_from_constants(&mut builder, &message_commitment);
    let root_c_bytes = bytes_from_constants(&mut builder, &signature.root_c);
    let root_s_bytes = bytes_from_constants(&mut builder, &signature.root_s);
    let root_h_bytes = bytes_from_constants(&mut builder, &signature.root_h);
    let s_sum_raw = field_utils::field2_to_bytes(&signature.s_sum);
    let s_sum_bytes = bytes_from_constants(&mut builder, &s_sum_raw);

    let mu_c0_idx = builder.alloc(signature.mu.c0);
    let mu_c1_idx = builder.alloc(signature.mu.c1);

    let mut contrib_c0_terms = Vec::new();
    let mut contrib_c1_terms = Vec::new();

    let mut t_var_indices = Vec::with_capacity(signature.t_values.len());
    for row in &signature.t_values {
        let mut row_indices = Vec::with_capacity(row.len());
        for &value in row {
            row_indices.push(builder.alloc(value));
        }
        t_var_indices.push(row_indices);
    }
    let t_matrix_bytes =
        serialize_field_matrix_bytes(&mut builder, &t_var_indices, &signature.t_values)?;
    trace_stage(&format!(
        "allocated {} t-value rows (max row len {})",
        t_var_indices.len(),
        signature
            .t_values
            .iter()
            .map(|row| row.len())
            .max()
            .unwrap_or(0)
    ));

    let mut o_var_indices = vec![Vec::with_capacity(params.m); params.n];

    // allocate evaluation tables
    let mut c_prime_vars = Vec::with_capacity(signature.c_prime_evals.len());
    for row in &signature.c_prime_evals {
        let mut row_vars = Vec::with_capacity(row.len());
        for &value in row {
            row_vars.push(builder.alloc_f2(value));
        }
        c_prime_vars.push(row_vars);
    }

    let mut pi_row_vars = Vec::with_capacity(signature.pi_rows.len());
    for row in &signature.pi_rows {
        let mut row_vars = Vec::with_capacity(row.len());
        for &value in row {
            row_vars.push(builder.alloc_f2(value));
        }
        pi_row_vars.push(row_vars);
    }

    let mut s_vars = Vec::with_capacity(signature.s_evals.len());
    for &value in &signature.s_evals {
        s_vars.push(builder.alloc_f2(value));
    }
    builder.enforce_f2_sum_equals_const(&s_vars, signature.s_sum);
    let s_leaves = build_f2_vector_leaves(&mut builder, &s_vars, &signature.s_evals);
    let s_root = merkle_root_from_leaves(&mut builder, &s_leaves);
    enforce_digest_equals_bytes(&mut builder, &s_root, &signature.root_s);
    trace_stage("s(u) Merkle root enforced");

    let mut h_vars = Vec::with_capacity(signature.h_evals.len());
    for &value in &signature.h_evals {
        h_vars.push(builder.alloc_f2(value));
    }
    let h_leaves = build_f2_vector_leaves(&mut builder, &h_vars, &signature.h_evals);
    let h_root = merkle_root_from_leaves(&mut builder, &h_leaves);
    enforce_digest_equals_bytes(&mut builder, &h_root, &signature.root_h);
    trace_stage("h(u) Merkle root enforced");
    let mut p_vars = Vec::with_capacity(signature.p_evals.len());
    for &value in &signature.p_evals {
        p_vars.push(builder.alloc_f2(value));
    }
    let mut f_prime_vars = Vec::with_capacity(signature.f_prime_evals.len());
    for &value in &signature.f_prime_evals {
        f_prime_vars.push(builder.alloc_f2(value));
    }

    let mut f0_vars = Vec::with_capacity(signature.f0_evals.len());
    for &value in &signature.f0_evals {
        f0_vars.push(builder.alloc_f2(value));
    }

    let mut fri_codeword_vars = Vec::with_capacity(signature.fri_codewords.len());
    for layer in &signature.fri_codewords {
        let mut layer_vars = Vec::with_capacity(layer.len());
        for &value in layer {
            layer_vars.push(builder.alloc_f2(value));
        }
        fri_codeword_vars.push(layer_vars);
    }

    let mut fri_row_vars = Vec::with_capacity(signature.fri_rows.len());
    for row_layer in &signature.fri_rows {
        let mut layer_rows = Vec::with_capacity(row_layer.len());
        for row in row_layer {
            let mut row_vars = Vec::with_capacity(row.len());
            for &value in row {
                row_vars.push(builder.alloc_f2(value));
            }
            layer_rows.push(row_vars);
        }
        if layer_rows.len() != pi_row_vars.len() {
            return Err(LoquatError::verification_failure(
                "Π row count mismatch in FRI rows",
            ));
        }
        fri_row_vars.push(layer_rows);
    }

    let c_merkle_leaves =
        build_c_merkle_leaves(&mut builder, &c_prime_vars, &signature.c_prime_evals);
    let c_merkle_root = merkle_root_from_leaves(&mut builder, &c_merkle_leaves);
    enforce_digest_equals_bytes(&mut builder, &c_merkle_root, &signature.root_c);
    trace_stage("c'(u) Merkle root enforced");

    for (layer_idx, layer_vars) in fri_codeword_vars.iter().enumerate() {
        let leaves = build_fri_layer_leaves(
            &mut builder,
            layer_vars,
            &signature.fri_codewords[layer_idx],
        );
        let root = merkle_root_from_leaves(&mut builder, &leaves);
        enforce_digest_equals_bytes(
            &mut builder,
            &root,
            &signature.ldt_proof.commitments[layer_idx],
        );
    }
    trace_stage("FRI layer commitments enforced");

    let q_hat_on_u = compute_q_hat_on_u(params, &transcript_data)?;
    let h_order = params.coset_h.len() as u128;
    let z_h_constant = params.h_shift.pow(h_order);
    let z_h_on_u: Vec<F2> = params
        .coset_u
        .iter()
        .map(|&u| u.pow(h_order) - z_h_constant)
        .collect();
    let h_size_scalar = F2::new(F::new(params.coset_h.len() as u128), F::zero());
    let z_mu_plus_s = transcript_data.z_challenge * signature.mu + signature.s_sum;
    let z_mu_plus_s_var = builder.alloc_f2(z_mu_plus_s);
    let mut f_on_u_vars = Vec::with_capacity(params.coset_u.len());
    let mut f_on_u_values = Vec::with_capacity(params.coset_u.len());
    for idx in 0..params.coset_u.len() {
        let mut partial_var: Option<F2Var> = None;
        let mut partial_value = F2::zero();
        for j in 0..params.n {
            let c_value = signature.c_prime_evals[j][idx];
            let q_value = q_hat_on_u[j][idx];
            let prod_value = c_value * q_value;
            let prod_var = builder.alloc_f2(prod_value);
            enforce_f2_const_mul_eq(&mut builder, c_prime_vars[j][idx], q_value, prod_var);

            let epsilon = transcript_data.epsilon_vals[j];
            let eps_value = prod_value * epsilon;
            let eps_var = builder.alloc_f2(eps_value);
            enforce_f2_const_mul_eq(&mut builder, prod_var, epsilon, eps_var);

            match partial_var.take() {
                None => {
                    partial_var = Some(eps_var);
                    partial_value = eps_value;
                }
                Some(prev_var) => {
                    let new_value = partial_value + eps_value;
                    let new_var = builder.alloc_f2(new_value);
                    enforce_f2_add(&mut builder, prev_var, eps_var, new_var);
                    partial_var = Some(new_var);
                    partial_value = new_value;
                }
            }
        }
        let final_var = partial_var.expect("at least one term");
        f_on_u_vars.push(final_var);
        f_on_u_values.push(partial_value);
    }

    // Π₀ rows relations
    for idx in 0..params.coset_u.len() {
        let sum_inputs: Vec<F2Var> = c_prime_vars.iter().map(|row| row[idx]).collect();
        builder.enforce_f2_sum_equals_unit(&sum_inputs, pi_row_vars[0][idx]);
        builder.enforce_f2_eq(pi_row_vars[1][idx], s_vars[idx]);
        builder.enforce_f2_eq(pi_row_vars[2][idx], h_vars[idx]);
        builder.enforce_f2_eq(pi_row_vars[3][idx], p_vars[idx]);
    }

    // Π₁ rows scaling constraints
    for row_idx in 0..4 {
        let exponent = params
            .rho_star_num
            .checked_sub(params.rho_numerators[row_idx])
            .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_i"))?
            as u128;
        for (col_idx, &y) in params.coset_u.iter().enumerate() {
            let scalar = y.pow(exponent);
            enforce_f2_const_mul_eq(
                &mut builder,
                pi_row_vars[row_idx][col_idx],
                scalar,
                pi_row_vars[row_idx + 4][col_idx],
            );
        }
    }

    for j in 0..params.n {
        let epsilon = transcript_data.epsilon_vals[j];
        for i in 0..params.m {
            let lambda = transcript_data.lambda_scalars[j * params.m + i];
            let o_val = signature.o_values[j][i];
            let o_idx = builder.alloc(o_val);
            o_var_indices[j].push(o_idx);

            let prod_val = lambda * o_val;
            let prod_idx = builder.alloc(prod_val);
            builder.enforce_mul_const_var(lambda, o_idx, prod_idx);

            let contrib0_val = prod_val * epsilon.c0;
            let contrib0_idx = builder.alloc(contrib0_val);
            builder.enforce_mul_const_var(epsilon.c0, prod_idx, contrib0_idx);
            contrib_c0_terms.push((contrib0_idx, F::one()));

            let contrib1_val = prod_val * epsilon.c1;
            let contrib1_idx = builder.alloc(contrib1_val);
            builder.enforce_mul_const_var(epsilon.c1, prod_idx, contrib1_idx);
            contrib_c1_terms.push((contrib1_idx, F::one()));
        }
    }

    let two = F::new(2);
    let two_inv = two
        .inverse()
        .ok_or_else(|| LoquatError::invalid_parameters("field has characteristic two"))?;
    let legendre_consts = LegendreConstants { two, two_inv };
    for j in 0..params.n {
        for i in 0..params.m {
            let pk_index = transcript_data.i_indices[j * params.m + i];
            let pk_value = *public_key
                .get(pk_index)
                .ok_or_else(|| LoquatError::invalid_parameters("public key index out of range"))?;
            enforce_legendre_constraint(
                &mut builder,
                o_var_indices[j][i],
                signature.o_values[j][i],
                t_var_indices[j][i],
                signature.t_values[j][i],
                pk_value,
                &legendre_consts,
            )?;
        }
    }

    let o_matrix_bytes =
        serialize_field_matrix_bytes(&mut builder, &o_var_indices, &signature.o_values)?;
    trace_stage("allocated o-value matrix inside circuit");
    enforce_transcript_relations(
        &mut builder,
        signature,
        &message_bytes,
        &message_commitment_bytes,
        &root_c_bytes,
        &t_matrix_bytes,
        &o_matrix_bytes,
        &root_s_bytes,
        &s_sum_bytes,
        &root_h_bytes,
    )?;
    trace_stage("Fiat-Shamir transcript replay enforced");

    builder.enforce_sum_equals(&contrib_c0_terms, mu_c0_idx);
    builder.enforce_sum_equals(&contrib_c1_terms, mu_c1_idx);

    for idx in 0..params.coset_u.len() {
        let zf_value = transcript_data.z_challenge * f_on_u_values[idx];
        let zf_var = builder.alloc_f2(zf_value);
        enforce_f2_const_mul_eq(
            &mut builder,
            f_on_u_vars[idx],
            transcript_data.z_challenge,
            zf_var,
        );

        let expected_value = zf_value + signature.s_evals[idx];
        let expected_var = builder.alloc_f2(expected_value);
        enforce_f2_add(&mut builder, zf_var, s_vars[idx], expected_var);

        builder.enforce_f2_eq(expected_var, f_prime_vars[idx]);

        let z_h_val = z_h_on_u[idx];
        let zh_h_value = z_h_val * signature.h_evals[idx];
        let zh_h_var = builder.alloc_f2(zh_h_value);
        enforce_f2_const_mul_eq(&mut builder, h_vars[idx], z_h_val, zh_h_var);

        let g_value = signature.f_prime_evals[idx] - zh_h_value;
        let g_var = builder.alloc_f2(g_value);
        builder.enforce_f2_sub(f_prime_vars[idx], zh_h_var, g_var);

        let hsize_g_value = h_size_scalar * g_value;
        let hsize_g_var = builder.alloc_f2(hsize_g_value);
        enforce_f2_const_mul_eq(&mut builder, g_var, h_size_scalar, hsize_g_var);

        let numerator_value = hsize_g_value - z_mu_plus_s;
        let numerator_var = builder.alloc_f2(numerator_value);
        builder.enforce_f2_sub(hsize_g_var, z_mu_plus_s_var, numerator_var);

        let denom_scalar = h_size_scalar * params.coset_u[idx];
        enforce_f2_const_mul_eq(&mut builder, p_vars[idx], denom_scalar, numerator_var);
    }

    // sumcheck claimed sum equals μ
    let mut last_sum = builder.alloc_f2(signature.pi_us.claimed_sum);
    builder.enforce_eq(last_sum.c0, mu_c0_idx);
    builder.enforce_eq(last_sum.c1, mu_c1_idx);
    if signature.pi_us.round_polynomials.len() != transcript_data.sumcheck_challenges.len() {
        return Err(LoquatError::verification_failure(
            "sumcheck challenge count mismatch",
        ));
    }
    for (round_idx, round_poly) in signature.pi_us.round_polynomials.iter().enumerate() {
        let c0_var = builder.alloc_f2(round_poly.c0);
        let c1_var = builder.alloc_f2(round_poly.c1);
        last_sum = enforce_sumcheck_round(
            &mut builder,
            last_sum,
            c0_var,
            c1_var,
            round_poly.c0,
            round_poly.c1,
            transcript_data.sumcheck_challenges[round_idx],
            two,
        );
    }
    trace_stage("sumcheck rounds enforced");

    let final_eval_var = builder.alloc_f2(signature.pi_us.final_evaluation);
    builder.enforce_f2_eq(last_sum, final_eval_var);

    // f^(0) linear combination
    for col_idx in 0..params.coset_u.len() {
        let pi_column: Vec<F2Var> = pi_row_vars.iter().map(|row| row[col_idx]).collect();
        enforce_f0_linear_combination(
            &mut builder,
            f0_vars[col_idx],
            &pi_column,
            &signature.e_vector,
        );
    }

    enforce_ldt_queries(
        &mut builder,
        params,
        signature,
        &fri_codeword_vars,
        &fri_row_vars,
    )?;
    trace_stage("enforced all LDT queries");

    trace_stage(&format!(
        "finalizing R1CS: vars={} constraints={}",
        builder.witness.len() + 1,
        builder.constraints.len()
    ));
    builder.finalize()
}

fn enforce_legendre_constraint(
    builder: &mut R1csBuilder,
    o_idx: usize,
    o_value: F,
    t_idx: usize,
    t_value: F,
    pk_value: F,
    constants: &LegendreConstants,
) -> LoquatResult<()> {
    let (ls_idx, ls_value) = enforce_legendre_symbol(builder, o_idx, o_value);
    let (prf_idx, _) = enforce_prf_from_symbol(builder, ls_idx, ls_value, constants)?;
    let expected_idx = enforce_expected_relation(builder, t_idx, t_value, pk_value, constants.two)?;
    builder.enforce_eq(prf_idx, expected_idx);
    Ok(())
}

fn enforce_legendre_symbol(
    builder: &mut R1csBuilder,
    base_idx: usize,
    base_value: F,
) -> (usize, F) {
    if LEGENDRE_EXPONENT_ITERS == 0 {
        return (base_idx, base_value);
    }
    let mut current_idx = base_idx;
    let mut current_value = base_value;
    for _ in 0..LEGENDRE_EXPONENT_ITERS {
        let square_value = current_value * current_value;
        let square_idx = builder.alloc(square_value);
        builder.enforce_mul_vars(current_idx, current_idx, square_idx);

        let mul_value = square_value * base_value;
        let mul_idx = builder.alloc(mul_value);
        builder.enforce_mul_vars(square_idx, base_idx, mul_idx);

        current_idx = mul_idx;
        current_value = mul_value;
    }
    (current_idx, current_value)
}

fn enforce_prf_from_symbol(
    builder: &mut R1csBuilder,
    ls_idx: usize,
    ls_value: F,
    constants: &LegendreConstants,
) -> LoquatResult<(usize, F)> {
    let ls_squared_value = ls_value * ls_value;
    let ls_squared_idx = builder.alloc(ls_squared_value);
    builder.enforce_mul_vars(ls_idx, ls_idx, ls_squared_idx);

    let is_zero_value = F::one() - ls_squared_value;
    let is_zero_idx = builder.alloc(is_zero_value);
    builder.enforce_linear_relation(
        &[(is_zero_idx, F::one()), (ls_squared_idx, F::one())],
        -F::one(),
    );
    builder.enforce_boolean(is_zero_idx);

    let non_zero_value = F::one() - is_zero_value;
    let non_zero_idx = builder.alloc(non_zero_value);
    builder.enforce_linear_relation(
        &[(non_zero_idx, F::one()), (is_zero_idx, F::one())],
        -F::one(),
    );

    let one_minus_ls_value = F::one() - ls_value;
    let one_minus_ls_idx = builder.alloc(one_minus_ls_value);
    builder.enforce_linear_relation(
        &[(one_minus_ls_idx, F::one()), (ls_idx, F::one())],
        -F::one(),
    );

    let half_term_value = constants.two_inv * one_minus_ls_value;
    let half_term_idx = builder.alloc(half_term_value);
    builder.enforce_mul_const_var(constants.two_inv, one_minus_ls_idx, half_term_idx);

    let prf_value = non_zero_value * half_term_value;
    let prf_idx = builder.alloc(prf_value);
    builder.enforce_mul_vars(non_zero_idx, half_term_idx, prf_idx);

    Ok((prf_idx, prf_value))
}

fn enforce_expected_relation(
    builder: &mut R1csBuilder,
    t_idx: usize,
    t_value: F,
    pk_value: F,
    two_const: F,
) -> LoquatResult<usize> {
    let two_pk = two_const * pk_value;
    let two_pk_t_value = two_pk * t_value;
    let two_pk_t_idx = builder.alloc(two_pk_t_value);
    builder.enforce_mul_const_var(two_pk, t_idx, two_pk_t_idx);

    let expected_value = pk_value + t_value - two_pk_t_value;
    let expected_idx = builder.alloc(expected_value);
    builder.enforce_linear_relation(
        &[
            (expected_idx, F::one()),
            (t_idx, -F::one()),
            (two_pk_t_idx, F::one()),
        ],
        -pk_value,
    );

    Ok(expected_idx)
}

fn enforce_sumcheck_round(
    builder: &mut R1csBuilder,
    last_sum: F2Var,
    c0_var: F2Var,
    c1_var: F2Var,
    c0_value: F2,
    c1_value: F2,
    challenge: F2,
    two_const: F,
) -> F2Var {
    builder.enforce_linear_relation(
        &[
            (last_sum.c0, F::one()),
            (c0_var.c0, -two_const),
            (c1_var.c0, -F::one()),
        ],
        F::zero(),
    );
    builder.enforce_linear_relation(
        &[
            (last_sum.c1, F::one()),
            (c0_var.c1, -two_const),
            (c1_var.c1, -F::one()),
        ],
        F::zero(),
    );

    let challenge_prod_value = c1_value * challenge;
    let challenge_prod_var = builder.alloc_f2(challenge_prod_value);
    enforce_f2_const_mul_eq(builder, c1_var, challenge, challenge_prod_var);

    let next_sum_value = c0_value + challenge_prod_value;
    let next_sum_var = builder.alloc_f2(next_sum_value);
    enforce_f2_add(builder, c0_var, challenge_prod_var, next_sum_var);

    next_sum_var
}

fn enforce_f2_const_mul_eq(builder: &mut R1csBuilder, source: F2Var, scalar: F2, target: F2Var) {
    let real_terms = vec![
        (target.c0, F::one()),
        (source.c0, -scalar.c0),
        (source.c1, scalar.c1),
    ];
    builder.enforce_linear_relation(&real_terms, F::zero());

    let imag_terms = vec![
        (target.c1, F::one()),
        (source.c1, -scalar.c0),
        (source.c0, -scalar.c1),
    ];
    builder.enforce_linear_relation(&imag_terms, F::zero());
}

fn enforce_f2_add(builder: &mut R1csBuilder, left: F2Var, right: F2Var, target: F2Var) {
    builder.enforce_linear_relation(
        &[
            (target.c0, F::one()),
            (left.c0, -F::one()),
            (right.c0, -F::one()),
        ],
        F::zero(),
    );
    builder.enforce_linear_relation(
        &[
            (target.c1, F::one()),
            (left.c1, -F::one()),
            (right.c1, -F::one()),
        ],
        F::zero(),
    );
}

fn enforce_f0_linear_combination(
    builder: &mut R1csBuilder,
    f0_var: F2Var,
    row_vars: &[F2Var],
    coeffs: &[F2],
) {
    let mut real_terms = vec![(f0_var.c0, F::one())];
    let mut imag_terms = vec![(f0_var.c1, F::one())];
    for (row_var, coeff) in row_vars.iter().zip(coeffs.iter()) {
        real_terms.push((row_var.c0, -coeff.c0));
        real_terms.push((row_var.c1, coeff.c1));
        imag_terms.push((row_var.c1, -coeff.c0));
        imag_terms.push((row_var.c0, -coeff.c1));
    }
    builder.enforce_linear_relation(&real_terms, F::zero());
    builder.enforce_linear_relation(&imag_terms, F::zero());
}

fn trace_stage(message: &str) {
    loquat_debug!("[r1cs] {}", message);
}

fn bytes_from_constants(builder: &mut R1csBuilder, data: &[u8]) -> Vec<Byte> {
    data.iter()
        .map(|&value| Byte::from_constant(builder, value))
        .collect()
}

fn enforce_byte_equality(builder: &mut R1csBuilder, left: &Byte, right: &Byte) {
    for bit in 0..8 {
        builder.enforce_eq(left.bits[bit], right.bits[bit]);
    }
}

fn enforce_ldt_queries(
    builder: &mut R1csBuilder,
    params: &LoquatPublicParams,
    signature: &LoquatSignature,
    fri_codeword_vars: &[Vec<F2Var>],
    fri_row_vars: &[Vec<Vec<F2Var>>],
) -> LoquatResult<()> {
    if params.eta >= usize::BITS as usize {
        return Err(LoquatError::invalid_parameters(
            "η parameter exceeds machine word size",
        ));
    }
    let chunk_size = 1usize << params.eta;
    if chunk_size == 0 {
        return Err(LoquatError::invalid_parameters(
            "chunk size computed as zero",
        ));
    }
    let final_commitment = signature
        .ldt_proof
        .commitments
        .last()
        .copied()
        .ok_or_else(|| LoquatError::verification_failure("missing final LDT commitment"))?;
    let num_rounds = params.r;

    for (_opening_idx, opening) in signature.ldt_proof.openings.iter().enumerate() {
        if opening.codeword_chunks.len() != num_rounds || opening.row_chunks.len() != num_rounds {
            return Err(LoquatError::verification_failure(
                "LDT opening does not contain all rounds",
            ));
        }
        let mut fold_index = opening.position;
        if fold_index
            >= signature
                .fri_codewords
                .first()
                .map(|layer| layer.len())
                .unwrap_or(0)
        {
            return Err(LoquatError::verification_failure(
                "LDT query position out of range",
            ));
        }

        for round in 0..num_rounds {
            let layer = signature
                .fri_codewords
                .get(round)
                .ok_or_else(|| LoquatError::verification_failure("missing FRI layer"))?;
            let next_layer_vars = fri_codeword_vars
                .get(round + 1)
                .ok_or_else(|| LoquatError::verification_failure("missing next FRI layer"))?;
            let layer_len = layer.len();
            if layer_len == 0 {
                return Err(LoquatError::verification_failure(
                    "FRI layer has zero length",
                ));
            }

            let chunk_len_candidate = chunk_size.min(layer_len);
            let chunk_start = if layer_len > chunk_size {
                (fold_index / chunk_size) * chunk_size
            } else {
                0
            };
            let chunk_end = (chunk_start + chunk_len_candidate).min(layer_len);
            if chunk_end <= chunk_start {
                return Err(LoquatError::verification_failure(
                    "invalid chunk range in FRI layer",
                ));
            }
            let chunk_len = chunk_end - chunk_start;
            let provided_chunk = &opening.codeword_chunks[round];
            if provided_chunk.len() != chunk_len {
                return Err(LoquatError::verification_failure(
                    "codeword chunk length mismatch",
                ));
            }

            let challenge = signature
                .fri_challenges
                .get(round)
                .copied()
                .ok_or_else(|| LoquatError::verification_failure("missing FRI challenge"))?;
            let mut coeff = F2::one();
            let mut folded_var: Option<F2Var> = None;
            let mut folded_value = F2::zero();

            for (offset, provided_value) in provided_chunk.iter().enumerate() {
                let provided_var = builder.alloc_f2(*provided_value);
                builder.enforce_f2_eq(provided_var, fri_codeword_vars[round][chunk_start + offset]);

                let term_value = *provided_value * coeff;
                let term_var = builder.alloc_f2(term_value);
                enforce_f2_const_mul_eq(builder, provided_var, coeff, term_var);

                folded_var = Some(match folded_var {
                    None => {
                        folded_value = term_value;
                        term_var
                    }
                    Some(prev_var) => {
                        let new_value = folded_value + term_value;
                        let new_var = builder.alloc_f2(new_value);
                        enforce_f2_add(builder, prev_var, term_var, new_var);
                        folded_value = new_value;
                        new_var
                    }
                });
                coeff *= challenge;
            }

            let folded_var =
                folded_var.ok_or_else(|| LoquatError::verification_failure("empty chunk"))?;

            let next_index = if layer_len > chunk_size {
                fold_index / chunk_size
            } else {
                0
            };
            let next_var = next_layer_vars
                .get(next_index)
                .copied()
                .ok_or_else(|| LoquatError::verification_failure("next index out of range"))?;
            builder.enforce_f2_eq(folded_var, next_var);

            let row_chunks = &opening.row_chunks[round];
            let expected_rows = signature
                .fri_rows
                .get(round)
                .ok_or_else(|| LoquatError::verification_failure("missing FRI row layer"))?;
            if row_chunks.len() != expected_rows.len() {
                return Err(LoquatError::verification_failure(
                    "row chunk count mismatch",
                ));
            }

            for (row_idx, chunk_values) in row_chunks.iter().enumerate() {
                if chunk_values.len() != chunk_len {
                    return Err(LoquatError::verification_failure(
                        "row chunk length mismatch",
                    ));
                }
                let expected_row_vars = &fri_row_vars[round][row_idx];
                let mut coeff = F2::one();
                let mut row_fold_var: Option<F2Var> = None;
                let mut row_fold_value = F2::zero();

                for (offset, &value) in chunk_values.iter().enumerate() {
                    let chunk_var = builder.alloc_f2(value);
                    builder.enforce_f2_eq(chunk_var, expected_row_vars[chunk_start + offset]);

                    let term_value = value * coeff;
                    let term_var = builder.alloc_f2(term_value);
                    enforce_f2_const_mul_eq(builder, chunk_var, coeff, term_var);

                    row_fold_var = Some(match row_fold_var {
                        None => {
                            row_fold_value = term_value;
                            term_var
                        }
                        Some(prev_var) => {
                            let new_value = row_fold_value + term_value;
                            let new_var = builder.alloc_f2(new_value);
                            enforce_f2_add(builder, prev_var, term_var, new_var);
                            row_fold_value = new_value;
                            new_var
                        }
                    });
                    coeff *= challenge;
                }

                let row_fold_var = row_fold_var.ok_or_else(|| {
                    LoquatError::verification_failure("empty row chunk encountered")
                })?;
                let next_row_var = fri_row_vars[round + 1][row_idx]
                    .get(next_index)
                    .copied()
                    .ok_or_else(|| {
                        LoquatError::verification_failure("next row index out of range")
                    })?;
                builder.enforce_f2_eq(row_fold_var, next_row_var);
            }

            fold_index = if layer_len > chunk_size {
                fold_index / chunk_size
            } else {
                0
            };
        }

        let final_layer_vars = fri_codeword_vars
            .last()
            .ok_or_else(|| LoquatError::verification_failure("missing final FRI layer"))?;
        if fold_index >= final_layer_vars.len() {
            return Err(LoquatError::verification_failure(
                "final FRI index out of range",
            ));
        }

        let final_value_var = final_layer_vars[fold_index];
        let final_eval_var = builder.alloc_f2(opening.final_eval);
        builder.enforce_f2_eq(final_eval_var, final_value_var);

        let leaf_bytes = bytes_from_f2(builder, final_eval_var, opening.final_eval);
        let root_bits = merkle_path_opening(builder, &leaf_bytes, &opening.auth_path, fold_index);
        enforce_digest_equals_bytes(builder, &root_bits, &final_commitment);
    }

    Ok(())
}

fn xor_words(builder: &mut R1csBuilder, left: &BitWord, right: &BitWord) -> BitWord {
    let len = left.len();
    let mut bits = Vec::with_capacity(len);
    for i in 0..len {
        let (bit_idx, _) = builder.xor_bits(
            left.bits[i],
            right.bits[i],
            left.bit_value(i),
            right.bit_value(i),
        );
        bits.push(bit_idx);
    }
    BitWord {
        bits,
        value: left.value ^ right.value,
    }
}

fn choice_word(builder: &mut R1csBuilder, x: &BitWord, y: &BitWord, z: &BitWord) -> BitWord {
    let len = x.len();
    let mut bits = Vec::with_capacity(len);
    let mut value = 0u32;
    for i in 0..len {
        let (bit_idx, bit_val) = builder.choice_bits(
            x.bits[i],
            y.bits[i],
            z.bits[i],
            x.bit_value(i),
            y.bit_value(i),
            z.bit_value(i),
        );
        if bit_val {
            value |= 1 << i;
        }
        bits.push(bit_idx);
    }
    BitWord { bits, value }
}

fn majority_word(builder: &mut R1csBuilder, a: &BitWord, b: &BitWord, c: &BitWord) -> BitWord {
    let len = a.len();
    let mut bits = Vec::with_capacity(len);
    let mut value = 0u32;
    for i in 0..len {
        let (bit_idx, bit_val) = builder.majority_bits(
            a.bits[i],
            b.bits[i],
            c.bits[i],
            a.bit_value(i),
            b.bit_value(i),
            c.bit_value(i),
        );
        if bit_val {
            value |= 1 << i;
        }
        bits.push(bit_idx);
    }
    BitWord { bits, value }
}

fn add_word_pair(builder: &mut R1csBuilder, left: &BitWord, right: &BitWord) -> BitWord {
    let len = left.len();
    let mut result_bits = Vec::with_capacity(len);
    let mut carry_idx = builder.alloc_bit(false);
    let mut carry_val = false;
    for i in 0..len {
        let (sum_idx, _sum_val) = builder.xor3_bits(
            left.bits[i],
            right.bits[i],
            carry_idx,
            left.bit_value(i),
            right.bit_value(i),
            carry_val,
        );
        result_bits.push(sum_idx);
        let (carry_idx_new, carry_val_new) = builder.majority_bits(
            left.bits[i],
            right.bits[i],
            carry_idx,
            left.bit_value(i),
            right.bit_value(i),
            carry_val,
        );
        carry_idx = carry_idx_new;
        carry_val = carry_val_new;
    }
    BitWord {
        bits: result_bits,
        value: left.value.wrapping_add(right.value),
    }
}

fn add_words(builder: &mut R1csBuilder, words: &[BitWord]) -> BitWord {
    let mut iter = words.iter();
    let mut acc = iter.next().expect("at least one word for addition").clone();
    for word in iter {
        acc = add_word_pair(builder, &acc, word);
    }
    acc
}

fn sigma_small_0(builder: &mut R1csBuilder, word: &BitWord) -> BitWord {
    let rot7 = word.rotate_right(7);
    let rot18 = word.rotate_right(18);
    let shr3 = word.shift_right(3, builder);
    let tmp = xor_words(builder, &rot7, &rot18);
    xor_words(builder, &tmp, &shr3)
}

fn sigma_small_1(builder: &mut R1csBuilder, word: &BitWord) -> BitWord {
    let rot17 = word.rotate_right(17);
    let rot19 = word.rotate_right(19);
    let shr10 = word.shift_right(10, builder);
    let tmp = xor_words(builder, &rot17, &rot19);
    xor_words(builder, &tmp, &shr10)
}

fn sigma_big_0(builder: &mut R1csBuilder, word: &BitWord) -> BitWord {
    let rot2 = word.rotate_right(2);
    let rot13 = word.rotate_right(13);
    let rot22 = word.rotate_right(22);
    let tmp = xor_words(builder, &rot2, &rot13);
    xor_words(builder, &tmp, &rot22)
}

fn sigma_big_1(builder: &mut R1csBuilder, word: &BitWord) -> BitWord {
    let rot6 = word.rotate_right(6);
    let rot11 = word.rotate_right(11);
    let rot25 = word.rotate_right(25);
    let tmp = xor_words(builder, &rot6, &rot11);
    xor_words(builder, &tmp, &rot25)
}

fn expand_message_schedule(
    builder: &mut R1csBuilder,
    initial_words: &[BitWord; 16],
) -> [BitWord; 64] {
    let mut schedule: Vec<BitWord> = initial_words.to_vec();
    for i in 16..64 {
        let s0 = sigma_small_0(builder, &schedule[i - 15]);
        let s1 = sigma_small_1(builder, &schedule[i - 2]);
        let sum = add_words(
            builder,
            &[s1, schedule[i - 7].clone(), s0, schedule[i - 16].clone()],
        );
        schedule.push(sum);
    }
    schedule.try_into().unwrap()
}

fn sha256_compress(builder: &mut R1csBuilder, chunk_words: &[BitWord; 16]) -> [BitWord; 8] {
    let mut state: Vec<BitWord> = SHA256_IV
        .iter()
        .map(|&value| BitWord::from_constant(builder, value))
        .collect();

    let schedule = expand_message_schedule(builder, chunk_words);

    for t in 0..64 {
        let s1 = sigma_big_1(builder, &state[4]);
        let ch = choice_word(builder, &state[4], &state[5], &state[6]);
        let k_word = BitWord::from_constant(builder, SHA256_K[t]);
        let temp1 = add_words(
            builder,
            &[state[7].clone(), s1, ch, k_word, schedule[t].clone()],
        );
        let s0 = sigma_big_0(builder, &state[0]);
        let maj = majority_word(builder, &state[0], &state[1], &state[2]);
        let temp2 = add_words(builder, &[s0, maj]);

        state[7] = state[6].clone();
        state[6] = state[5].clone();
        state[5] = state[4].clone();
        state[4] = add_word_pair(builder, &state[3], &temp1);
        state[3] = state[2].clone();
        state[2] = state[1].clone();
        state[1] = state[0].clone();
        state[0] = add_word_pair(builder, &temp1, &temp2);
    }

    for i in 0..8 {
        let const_word = BitWord::from_constant(builder, SHA256_IV[i]);
        state[i] = add_word_pair(builder, &state[i], &const_word);
    }

    state.try_into().unwrap()
}

fn bytes_from_field(builder: &mut R1csBuilder, var_idx: usize, value: F) -> Vec<Byte> {
    let bits = builder.decompose_to_bits(var_idx, value, 128);
    let mut bytes = Vec::with_capacity(16);
    let value_u128 = field_to_u128(value);
    for i in 0..16 {
        let mut byte_bits = [0usize; 8];
        let mut byte_value = 0u8;
        for bit in 0..8 {
            byte_bits[bit] = bits[i * 8 + bit];
            if ((value_u128 >> (i * 8 + bit)) & 1) == 1 {
                byte_value |= 1 << bit;
            }
        }
        bytes.push(Byte::from_bits(byte_bits, byte_value));
    }
    bytes
}

fn bytes_from_f2(builder: &mut R1csBuilder, var: F2Var, value: F2) -> Vec<Byte> {
    let mut bytes = bytes_from_field(builder, var.c0, value.c0);
    bytes.extend(bytes_from_field(builder, var.c1, value.c1));
    bytes
}

fn serialize_field_matrix_bytes(
    builder: &mut R1csBuilder,
    var_matrix: &[Vec<usize>],
    value_matrix: &[Vec<F>],
) -> LoquatResult<Vec<Byte>> {
    if var_matrix.len() != value_matrix.len() {
        return Err(LoquatError::verification_failure(
            "matrix row count mismatch for transcript serialization",
        ));
    }
    let mut bytes = bytes_from_constants(builder, &(var_matrix.len() as u32).to_le_bytes());
    for (row_vars, row_values) in var_matrix.iter().zip(value_matrix.iter()) {
        if row_vars.len() != row_values.len() {
            return Err(LoquatError::verification_failure(
                "matrix row length mismatch for transcript serialization",
            ));
        }
        bytes.extend(bytes_from_constants(
            builder,
            &(row_vars.len() as u32).to_le_bytes(),
        ));
        for (&var_idx, &value) in row_vars.iter().zip(row_values.iter()) {
            bytes.extend(bytes_from_field(builder, var_idx, value));
        }
    }
    Ok(bytes)
}

struct TranscriptCircuit {
    bytes: Vec<Byte>,
    counter: u64,
}

impl TranscriptCircuit {
    fn new(builder: &mut R1csBuilder, label: &[u8]) -> Self {
        let mut bytes = bytes_from_constants(builder, b"loquat.transcript");
        bytes.extend(bytes_from_constants(
            builder,
            &(label.len() as u64).to_le_bytes(),
        ));
        bytes.extend(bytes_from_constants(builder, label));
        Self { bytes, counter: 0 }
    }

    fn append_message(&mut self, builder: &mut R1csBuilder, label: &[u8], data: &[Byte]) {
        self.bytes.extend(bytes_from_constants(
            builder,
            &(label.len() as u64).to_le_bytes(),
        ));
        self.bytes.extend(bytes_from_constants(builder, label));
        self.bytes.extend(bytes_from_constants(
            builder,
            &(data.len() as u64).to_le_bytes(),
        ));
        self.bytes.extend(data.iter().cloned());
    }

    fn challenge(&mut self, builder: &mut R1csBuilder, label: &[u8]) -> Vec<Byte> {
        let mut input = self.bytes.clone();
        input.extend(bytes_from_constants(
            builder,
            &(label.len() as u64).to_le_bytes(),
        ));
        input.extend(bytes_from_constants(builder, label));
        input.extend(bytes_from_constants(builder, &self.counter.to_le_bytes()));
        input.extend(bytes_from_constants(builder, &(0u32).to_le_bytes()));
        let digest = sha256_hash_bytes(builder, &input);
        let digest_bytes = bytes_from_bitwords(&digest);
        self.counter = self.counter.wrapping_add(1);
        self.append_message(builder, label, &digest_bytes);
        digest_bytes
    }
}

fn enforce_field_matches_digest(
    builder: &mut R1csBuilder,
    digest_bytes: &[Byte],
    value: F,
) -> LoquatResult<()> {
    if digest_bytes.len() < 16 {
        return Err(LoquatError::verification_failure(
            "digest too short for field conversion",
        ));
    }
    let value_idx = builder.alloc(value);
    let value_bytes = bytes_from_field(builder, value_idx, value);
    for (expected, actual) in value_bytes.iter().zip(digest_bytes.iter()) {
        enforce_byte_equality(builder, expected, actual);
    }
    Ok(())
}

fn enforce_transcript_relations(
    builder: &mut R1csBuilder,
    signature: &LoquatSignature,
    message_bytes: &[Byte],
    message_commitment_bytes: &[Byte],
    root_c_bytes: &[Byte],
    t_matrix_bytes: &[Byte],
    o_matrix_bytes: &[Byte],
    root_s_bytes: &[Byte],
    s_sum_bytes: &[Byte],
    root_h_bytes: &[Byte],
) -> LoquatResult<()> {
    if signature.z_challenge.c1 != F::zero() {
        return Err(LoquatError::verification_failure(
            "z challenge imaginary component must be zero",
        ));
    }
    for (idx, entry) in signature.e_vector.iter().enumerate() {
        if entry.c1 != F::zero() {
            return Err(LoquatError::verification_failure(&format!(
                "e_vector[{}] imaginary component must be zero",
                idx
            )));
        }
    }

    let mut transcript = TranscriptCircuit::new(builder, b"loquat_signature");
    transcript.append_message(builder, b"message", message_bytes);
    transcript.append_message(builder, b"message_commitment", message_commitment_bytes);
    transcript.append_message(builder, b"root_c", root_c_bytes);
    transcript.append_message(builder, b"t_values", t_matrix_bytes);
    let _h1_bytes = transcript.challenge(builder, b"h1");

    transcript.append_message(builder, b"o_values", o_matrix_bytes);
    let _h2_bytes = transcript.challenge(builder, b"h2");

    transcript.append_message(builder, b"root_s", root_s_bytes);
    transcript.append_message(builder, b"s_sum", s_sum_bytes);
    let h3_bytes = transcript.challenge(builder, b"h3");
    enforce_field_matches_digest(builder, &h3_bytes[..16], signature.z_challenge.c0)?;

    transcript.append_message(builder, b"root_h", root_h_bytes);
    let h4_bytes = transcript.challenge(builder, b"h4");

    let domain_bytes = bytes_from_constants(builder, b"e_vector");
    for (idx, entry) in signature.e_vector.iter().enumerate() {
        let mut expand_input = h4_bytes.clone();
        expand_input.extend(domain_bytes.clone());
        expand_input.extend(bytes_from_constants(builder, &(idx as u32).to_le_bytes()));
        let digest = sha256_hash_bytes(builder, &expand_input);
        let digest_bytes = bytes_from_bitwords(&digest);
        enforce_field_matches_digest(builder, &digest_bytes[..16], entry.c0)?;
    }

    Ok(())
}

fn word_from_bytes(bytes: &[Byte; 4]) -> BitWord {
    let mut bits = Vec::with_capacity(32);
    let mut value = 0u32;
    for bit_pos in 0..32 {
        let byte_index = 3 - (bit_pos / 8);
        let bit_in_byte = bit_pos % 8;
        bits.push(bytes[byte_index].bits[bit_in_byte]);
        if ((bytes[byte_index].value >> bit_in_byte) & 1) == 1 {
            value |= 1 << bit_pos;
        }
    }
    BitWord { bits, value }
}

fn bytes_from_bitwords(words: &[BitWord; 8]) -> Vec<Byte> {
    let mut bytes = Vec::with_capacity(32);
    for word in words {
        for byte_index in 0..4 {
            let mut byte_bits = [0usize; 8];
            let mut byte_value = 0u8;
            for bit_in_byte in 0..8 {
                let word_bit = byte_index * 8 + bit_in_byte;
                byte_bits[bit_in_byte] = word.bits[word_bit];
                if ((word.value >> word_bit) & 1) == 1 {
                    byte_value |= 1 << bit_in_byte;
                }
            }
            bytes.push(Byte::from_bits(byte_bits, byte_value));
        }
    }
    bytes
}

fn sha256_hash_bytes(builder: &mut R1csBuilder, bytes: &[Byte]) -> [BitWord; 8] {
    let mut message = bytes.to_vec();
    let bit_len = (message.len() as u64) * 8;
    message.push(Byte::from_constant(builder, 0x80));
    while (message.len() % 64) != 56 {
        message.push(Byte::from_constant(builder, 0x00));
    }
    for shift in (0..8).rev() {
        let byte = ((bit_len >> (shift * 8)) & 0xff) as u8;
        message.push(Byte::from_constant(builder, byte));
    }

    let mut state = SHA256_IV
        .iter()
        .map(|&value| BitWord::from_constant(builder, value))
        .collect::<Vec<_>>();

    for chunk in message.chunks(64) {
        let mut words = core::array::from_fn(|_| BitWord {
            bits: Vec::new(),
            value: 0,
        });
        for (i, word_bytes) in chunk.chunks(4).enumerate() {
            let array_vec: Vec<Byte> = word_bytes.iter().cloned().collect();
            let array: [Byte; 4] = array_vec.try_into().unwrap();
            words[i] = word_from_bytes(&array);
        }
        let compressed = sha256_compress(builder, &words);
        state = compressed.to_vec();
    }

    state.try_into().unwrap()
}

fn enforce_digest_equals_bytes(
    builder: &mut R1csBuilder,
    digest: &[BitWord; 8],
    expected: &[u8; 32],
) {
    let bytes = bytes_from_bitwords(digest);
    for (byte, &expected_value) in bytes.iter().zip(expected.iter()) {
        for bit in 0..8 {
            let bit_idx = byte.bits[bit];
            let target = if ((expected_value >> bit) & 1) == 1 {
                F::one()
            } else {
                F::zero()
            };
            builder.enforce_linear_relation(&[(bit_idx, F::one())], -target);
        }
    }
}

fn merkle_root_from_leaves(builder: &mut R1csBuilder, leaves: &[Vec<Byte>]) -> [BitWord; 8] {
    let mut level: Vec<[BitWord; 8]> = leaves
        .iter()
        .map(|leaf| sha256_hash_bytes(builder, leaf))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            let mut bytes = bytes_from_bitwords(&chunk[0]);
            bytes.extend(bytes_from_bitwords(&chunk[1]));
            let digest = sha256_hash_bytes(builder, &bytes);
            next.push(digest);
        }
        level = next;
    }
    level.pop().unwrap()
}
fn build_c_merkle_leaves(
    builder: &mut R1csBuilder,
    c_prime_vars: &[Vec<F2Var>],
    c_prime_values: &[Vec<F2>],
) -> Vec<Vec<Byte>> {
    let leaf_count = c_prime_vars[0].len();
    let mut leaves = Vec::with_capacity(leaf_count);
    for idx in 0..leaf_count {
        let mut leaf_bytes = Vec::new();
        for j in 0..c_prime_vars.len() {
            leaf_bytes.extend(bytes_from_f2(
                builder,
                c_prime_vars[j][idx],
                c_prime_values[j][idx],
            ));
        }
        leaves.push(leaf_bytes);
    }
    leaves
}

fn build_f2_vector_leaves(
    builder: &mut R1csBuilder,
    vars: &[F2Var],
    values: &[F2],
) -> Vec<Vec<Byte>> {
    vars.iter()
        .zip(values.iter())
        .map(|(var, value)| bytes_from_f2(builder, *var, *value))
        .collect()
}

fn build_fri_layer_leaves(
    builder: &mut R1csBuilder,
    layer_vars: &[F2Var],
    layer_values: &[F2],
) -> Vec<Vec<Byte>> {
    layer_vars
        .iter()
        .zip(layer_values.iter())
        .map(|(var, value)| bytes_from_f2(builder, *var, *value))
        .collect()
}

fn compute_q_hat_on_u(
    params: &LoquatPublicParams,
    transcript_data: &TranscriptData,
) -> LoquatResult<Vec<Vec<F2>>> {
    let mut results = Vec::with_capacity(params.n);
    for j in 0..params.n {
        let mut q_eval_on_h = Vec::with_capacity(2 * params.m);
        for i in 0..params.m {
            let lambda_scalar = transcript_data.lambda_scalars[j * params.m + i];
            let lambda_f2 = F2::new(lambda_scalar, F::zero());
            let index = transcript_data.i_indices[j * params.m + i];
            let public_i = params.public_indices[index];
            let public_f2 = F2::new(public_i, F::zero());
            q_eval_on_h.push(lambda_f2);
            q_eval_on_h.push(lambda_f2 * public_f2);
        }
        let q_hat_coeffs = interpolate_on_coset(&q_eval_on_h, params.h_shift, params.h_generator)?;
        let mut padded = vec![F2::zero(); params.coset_u.len()];
        padded[..q_hat_coeffs.len()].copy_from_slice(&q_hat_coeffs);
        let q_hat_on_u = evaluate_on_coset(&padded, params.u_shift, params.u_generator)?;
        results.push(q_hat_on_u);
    }
    Ok(results)
}
