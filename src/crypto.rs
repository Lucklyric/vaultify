//! Cryptographic operations for the vault using Argon2id and AES-256-GCM.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{password_hash::rand_core::RngCore, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid base64 encoding")]
    InvalidBase64,
    #[error("Invalid salt length")]
    InvalidSaltLength,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
}

/// Handles all cryptographic operations for the vault.
pub struct VaultCrypto {
    // Argon2id parameters (tuned for desktop use)
    argon2_time_cost: u32,
    argon2_memory_cost: u32,
    argon2_parallelism: u32,
    argon2_hash_len: usize,
    argon2_salt_len: usize,
    // AES-GCM parameters
    aes_nonce_size: usize,
}

impl Default for VaultCrypto {
    fn default() -> Self {
        Self {
            argon2_time_cost: 2,
            argon2_memory_cost: 65536, // 64 MB
            argon2_parallelism: 1,
            argon2_hash_len: 32, // 256 bits for AES-256
            argon2_salt_len: 16, // 128 bits
            aes_nonce_size: 12,  // 96 bits (GCM standard)
        }
    }
}

impl VaultCrypto {
    /// Create a new VaultCrypto instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a new random salt.
    pub fn generate_salt(&self) -> Vec<u8> {
        let mut salt = vec![0u8; self.argon2_salt_len];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Encode salt as base64 for storage in vault file.
    pub fn encode_salt(salt: &[u8]) -> String {
        STANDARD.encode(salt)
    }

    /// Decode salt from base64.
    pub fn decode_salt(salt_b64: &str) -> Result<Vec<u8>, CryptoError> {
        STANDARD
            .decode(salt_b64)
            .map_err(|_| CryptoError::InvalidBase64)
    }

    /// Derive encryption key from password using Argon2id.
    /// Returns a key that will be automatically zeroed on drop.
    pub fn derive_key(&self, password: &str, salt: &[u8]) -> Result<DerivedKey, CryptoError> {
        if salt.len() != self.argon2_salt_len {
            return Err(CryptoError::InvalidSaltLength);
        }

        let params = Params::new(
            self.argon2_memory_cost,
            self.argon2_time_cost,
            self.argon2_parallelism,
            Some(self.argon2_hash_len),
        )
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let mut output = vec![0u8; self.argon2_hash_len];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut output)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        Ok(DerivedKey(output))
    }

    /// Encrypt plaintext using AES-256-GCM with per-item salt.
    /// Returns tuple of (base64-encoded ciphertext, salt used).
    pub fn encrypt(
        &self,
        plaintext: &str,
        password: &str,
    ) -> Result<(String, Vec<u8>), CryptoError> {
        self.encrypt_with_salt(plaintext, password, None)
    }

    /// Encrypt plaintext using AES-256-GCM with provided or generated salt.
    pub fn encrypt_with_salt(
        &self,
        plaintext: &str,
        password: &str,
        salt: Option<Vec<u8>>,
    ) -> Result<(String, Vec<u8>), CryptoError> {
        // Generate salt if not provided
        let salt = salt.unwrap_or_else(|| self.generate_salt());

        // Derive key
        let key = self.derive_key(password, &salt)?;

        // Create cipher
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));

        // Generate random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Combine nonce + ciphertext (tag is already appended by AESGCM)
        let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext);

        // Return base64 encoded ciphertext and salt
        Ok((STANDARD.encode(&combined), salt))
    }

    /// Decrypt base64-encoded ciphertext using provided salt.
    pub fn decrypt(
        &self,
        ciphertext_b64: &str,
        password: &str,
        salt: &[u8],
    ) -> Result<String, CryptoError> {
        // Decode from base64
        let combined = STANDARD
            .decode(ciphertext_b64)
            .map_err(|_| CryptoError::InvalidBase64)?;

        if combined.len() < self.aes_nonce_size {
            return Err(CryptoError::DecryptionFailed);
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = combined.split_at(self.aes_nonce_size);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Derive key
        let key = self.derive_key(password, salt)?;

        // Create cipher
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));

        // Decrypt
        let plaintext_bytes = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        // Convert to string
        String::from_utf8(plaintext_bytes).map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// A derived key that automatically zeroes itself on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey(Vec<u8>);

impl DerivedKey {
    /// Get a reference to the key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for DerivedKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_generation() {
        let crypto = VaultCrypto::new();
        let salt1 = crypto.generate_salt();
        let salt2 = crypto.generate_salt();

        assert_eq!(salt1.len(), 16); // 128 bits
        assert_eq!(salt2.len(), 16);
        assert_ne!(salt1, salt2); // Should be random
    }

    #[test]
    fn test_salt_encoding() {
        let crypto = VaultCrypto::new();
        let salt = crypto.generate_salt();
        let encoded = VaultCrypto::encode_salt(&salt);
        let decoded = VaultCrypto::decode_salt(&encoded).unwrap();

        assert_eq!(salt, decoded);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let crypto = VaultCrypto::new();
        let password = "test_password_123";
        let plaintext = "This is a secret message!";

        // Encrypt
        let (ciphertext, salt) = crypto.encrypt(plaintext, password).unwrap();
        assert!(!ciphertext.is_empty());
        assert_eq!(salt.len(), 16);

        // Decrypt
        let decrypted = crypto.decrypt(&ciphertext, password, &salt).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let crypto = VaultCrypto::new();
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let plaintext = "Secret data";

        let (ciphertext, salt) = crypto.encrypt(plaintext, password).unwrap();

        let result = crypto.decrypt(&ciphertext, wrong_password, &salt);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_derivation_consistency() {
        let crypto = VaultCrypto::new();
        let salt = crypto.generate_salt();
        let password = "consistent_password";

        let key1 = crypto.derive_key(password, &salt).unwrap();
        let key2 = crypto.derive_key(password, &salt).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_salts_produce_different_ciphertexts() {
        let crypto = VaultCrypto::new();
        let password = "test_password";
        let plaintext = "Same data";

        let (ciphertext1, salt1) = crypto.encrypt(plaintext, password).unwrap();
        let (ciphertext2, salt2) = crypto.encrypt(plaintext, password).unwrap();

        assert_ne!(salt1, salt2);
        assert_ne!(ciphertext1, ciphertext2);

        // Both should decrypt to the same plaintext
        assert_eq!(
            crypto.decrypt(&ciphertext1, password, &salt1).unwrap(),
            plaintext
        );
        assert_eq!(
            crypto.decrypt(&ciphertext2, password, &salt2).unwrap(),
            plaintext
        );
    }
}
