use std::collections::HashMap;

use ed25519_dalek::{SigningKey, VerifyingKey};

use rand_core::{OsRng, TryRngCore};

use crate::AuthError;

// =============================================================
// KEY RING
// =============================================================

/// Набор public keys,
/// которым PAYPHONE server доверяет.
///
/// private keys здесь НЕТ.
pub struct VerificationKeyRing {
    keys: HashMap<u32, VerifyingKey>,
}

impl VerificationKeyRing {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Добавляем public key.
    pub fn insert(&mut self, key_id: u32, key: VerifyingKey) {
        self.keys.insert(key_id, key);
    }

    pub fn get(&self, key_id: u32) -> Result<&VerifyingKey, AuthError> {
        self.keys
            .get(&key_id)
            .ok_or(AuthError::UnknownKeyId(key_id))
    }
}

impl Default for VerificationKeyRing {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================
// KEY GENERATION
// =============================================================

/// Генерирует новый Ed25519 signing key.
///
/// Используется ТОЛЬКО:
///
/// admin backend
/// token issuer
/// key rotation tooling
pub fn generate_signing_key() -> Result<SigningKey, rand_core::OsError> {
    let mut secret = [0u8; 32];

    OsRng.try_fill_bytes(&mut secret)?;

    Ok(SigningKey::from_bytes(&secret))
}
