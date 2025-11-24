use std::{env, time::Duration, time::Instant};

use bincode::serialize;
use serde::{Deserialize, Serialize};
use vc_pqc::snarks::{
    aurora_prove_with_options, aurora_verify, build_loquat_r1cs, AuroraParams, AuroraProverOptions,
};
use vc_pqc::{
    keygen_with_params, loquat_setup, loquat_sign, loquat_verify, LoquatSignature,
    LoquatSignatureArtifact, LoquatSigningTranscript,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FullTranscriptView {
    artifact: LoquatSignatureArtifact,
    transcript: Option<LoquatSigningTranscript>,
}

fn serialized_artifact_len(signature: &LoquatSignature) -> bincode::Result<usize> {
    Ok(serialize(&signature.artifact())?.len())
}

fn serialized_full_transcript_len(signature: &LoquatSignature) -> bincode::Result<usize> {
    let view = FullTranscriptView {
        artifact: signature.artifact(),
        transcript: signature.transcript.clone(),
    };
    Ok(serialize(&view)?.len())
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() == 0 {
        format!("{:.2} ms", duration.as_secs_f64() * 1_000.0)
    } else {
        format!("{:.3} s", duration.as_secs_f64())
    }
}

fn parse_args() -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let security = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(128);
    let message_len = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(32);
    Ok((security, message_len))
}

fn synthetic_message(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131) & 0xff) as u8).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (security_level, message_len) = parse_args()?;
    let message = synthetic_message(message_len);

    println!("=== Loquat SNARK Stats ===\n");
    println!(
        "security level: {}-bit   message bytes: {}",
        security_level, message_len
    );

    let params = loquat_setup(security_level)?;
    let keypair = keygen_with_params(&params)?;

    let sign_start = Instant::now();
    let signature = loquat_sign(&message, &keypair, &params)?;
    let sign_time = sign_start.elapsed();

    let verify_start = Instant::now();
    let is_valid = loquat_verify(&message, &signature, &keypair.public_key, &params)?;
    let verify_time = verify_start.elapsed();
    if !is_valid {
        eprintln!("signature failed to verify; aborting");
        return Ok(());
    }

    let artifact_bytes = serialized_artifact_len(&signature)?;
    let transcript_bytes = serialized_full_transcript_len(&signature)?;

    println!("\n--- Loquat signature ---");
    println!("  sign time:            {}", format_duration(sign_time));
    println!("  verify time:          {}", format_duration(verify_time));
    println!("  artifact size (B):    {:>10}", artifact_bytes);
    println!("  transcript size (B):  {:>10}", transcript_bytes);

    let (instance, witness) =
        build_loquat_r1cs(&message, &signature, &keypair.public_key, &params)?;
    println!("\n--- R1CS stats ---");
    println!("  variables:            {}", instance.num_variables);
    println!("  constraints:          {}", instance.constraints.len());

    let aurora_params = AuroraParams {
        constraint_query_count: 8,
        witness_query_count: 8,
    };
    let aurora_opts = AuroraProverOptions::default();

    let prove_start = Instant::now();
    let proof = aurora_prove_with_options(&instance, &witness, &aurora_params, &aurora_opts)?;
    let aurora_prove_time = prove_start.elapsed();

    let proof_bytes = serialize(&proof)?.len();
    let aurora_verify_start = Instant::now();
    let verify_result = aurora_verify(&instance, &proof, &aurora_params, None)?;
    let aurora_verify_time = aurora_verify_start.elapsed();

    println!("\n--- Aurora proof ---");
    println!(
        "  prove time:           {}",
        format_duration(aurora_prove_time)
    );
    println!(
        "  verify time:          {}",
        format_duration(aurora_verify_time)
    );
    println!("  proof size (B):       {:>10}", proof_bytes);
    println!(
        "  verification result:  {}",
        if verify_result.is_some() {
            "success"
        } else {
            "failure"
        }
    );

    Ok(())
}
