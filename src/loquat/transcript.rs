use sha2::{Digest, Sha256};

/// Minimal transcript implementation (Fiat-Shamir) compatible with no_std builds.
#[derive(Clone)]
pub struct Transcript {
    state: Sha256,
    counter: u64,
}

impl Transcript {
    pub fn new(label: &[u8]) -> Self {
        let mut state = Sha256::new();
        state.update(b"loquat.transcript");
        state.update(&(label.len() as u64).to_le_bytes());
        state.update(label);
        Self { state, counter: 0 }
    }

    pub fn append_message(&mut self, label: &[u8], data: &[u8]) {
        self.state.update(&(label.len() as u64).to_le_bytes());
        self.state.update(label);
        self.state.update(&(data.len() as u64).to_le_bytes());
        self.state.update(data);
    }

    pub fn challenge_bytes(&mut self, label: &[u8], output: &mut [u8]) {
        let mut offset = 0usize;
        let mut chunk_index: u32 = 0;
        while offset < output.len() {
            let mut hasher = self.state.clone();
            hasher.update(&(label.len() as u64).to_le_bytes());
            hasher.update(label);
            hasher.update(self.counter.to_le_bytes());
            hasher.update(chunk_index.to_le_bytes());
            let digest = hasher.finalize();
            let remaining = output.len() - offset;
            let take = remaining.min(digest.len());
            output[offset..offset + take].copy_from_slice(&digest[..take]);
            offset += take;
            chunk_index = chunk_index.wrapping_add(1);
        }
        self.append_message(label, output);
        self.counter = self.counter.wrapping_add(1);
    }
}
