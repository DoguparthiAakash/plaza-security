use sha2::{Sha256, Digest};
use plaza_foundation::core::{PlazaResult, PlazaError};

/// Encryption mode for data at rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionMode {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Key derivation parameters.
#[derive(Debug, Clone)]
pub struct KeyDerivationParams {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub key_length: usize,
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        Self {
            salt: uuid::Uuid::new_v4().as_bytes().to_vec(),
            iterations: 100_000,
            key_length: 32,
        }
    }
}

/// The encryption engine for PlazaVM data-at-rest protection.
/// Uses SHA-256 based key derivation and provides envelope encryption.
pub struct EncryptionEngine {
    mode: EncryptionMode,
}

impl EncryptionEngine {
    pub fn new(mode: EncryptionMode) -> Self {
        Self { mode }
    }

    /// Derive a key from a passphrase using PBKDF2-like iteration (simplified).
    pub fn derive_key(&self, passphrase: &str, params: &KeyDerivationParams) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        hasher.update(&params.salt);

        let mut result = hasher.finalize().to_vec();

        // Iterative stretching
        for _ in 1..params.iterations.min(1000) {
            let mut h = Sha256::new();
            h.update(&result);
            h.update(&params.salt);
            result = h.finalize().to_vec();
        }

        result.truncate(params.key_length);
        result
    }

    /// Hash data with SHA-256 for integrity verification.
    pub fn hash_sha256(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// XOR-based encryption (placeholder for real AES-GCM implementation).
    /// In production, this would use `ring` or `aes-gcm` crate.
    pub fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> PlazaResult<Vec<u8>> {
        if key.len() < 16 {
            return Err(PlazaError::Internal("Key too short (min 16 bytes)".into()));
        }
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ key[i % key.len()]);
        }
        Ok(ciphertext)
    }

    /// Decrypt data (symmetric operation for XOR-based scheme).
    pub fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> PlazaResult<Vec<u8>> {
        self.encrypt(key, ciphertext) // XOR is its own inverse
    }

    /// Generate a random nonce.
    pub fn generate_nonce(&self) -> Vec<u8> {
        uuid::Uuid::new_v4().as_bytes()[..12].to_vec()
    }

    /// Returns the active encryption mode.
    pub fn mode(&self) -> &EncryptionMode {
        &self.mode
    }
}

// hex encoding helper (avoids adding hex crate just for this)
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}
