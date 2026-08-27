use bytes::{Buf, BufMut, Bytes, BytesMut};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

// =============================================================
// CONSTANTS
// =============================================================

/// Первые 4 bytes любого PAYPHONE subscription token.
///
/// ASCII:
///
/// P A Y T
pub const TOKEN_MAGIC: [u8; 4] = *b"PAYT";

/// Первая версия формата token.
pub const TOKEN_VERSION: u8 = 1;

/// Размер UUID-подобных бинарных ID.
pub const TOKEN_ID_SIZE: usize = 16;
pub const CLIENT_ID_SIZE: usize = 16;

/// Ed25519 signature всегда 64 bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Размер части token,
/// которая подписывается.
///
/// magic         4
/// version       1
/// key_id        4
/// token_id     16
/// client_id    16
/// issued_at     8
/// not_before    8
/// expires_at    8
/// plan          1
/// device_limit  1
/// max_mbps      4
///
/// TOTAL = 71
pub const TOKEN_PAYLOAD_SIZE: usize = 71;

/// Полный размер:
///
/// 71 payload
/// +
/// 64 signature
///
/// = 135 bytes.
pub const TOKEN_SIZE: usize = TOKEN_PAYLOAD_SIZE + SIGNATURE_SIZE;

// =============================================================
// SUBSCRIPTION PLAN
// =============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SubscriptionPlan {
    Basic = 1,
    Pro = 2,
    Unlimited = 3,
}

impl TryFrom<u8> for SubscriptionPlan {
    type Error = AuthError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Basic),
            2 => Ok(Self::Pro),
            3 => Ok(Self::Unlimited),

            _ => Err(AuthError::UnknownPlan(value)),
        }
    }
}

// =============================================================
// TOKEN CLAIMS
// =============================================================

/// Claims — это данные,
/// которым сервер доверяет ТОЛЬКО
/// после успешной проверки signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionClaims {
    /// Какой signing key использовался.
    pub key_id: u32,

    /// Уникальный ID конкретного token.
    ///
    /// Используем для revocation.
    pub token_id: [u8; TOKEN_ID_SIZE],

    /// ID клиента / аккаунта.
    pub client_id: [u8; CLIENT_ID_SIZE],

    /// Когда token был выпущен.
    ///
    /// Unix timestamp seconds.
    pub issued_at: u64,

    /// Token нельзя использовать
    /// раньше этого момента.
    pub not_before: u64,

    /// После этого времени
    /// token недействителен.
    pub expires_at: u64,

    /// Тариф.
    pub plan: SubscriptionPlan,

    /// Максимальное число устройств.
    pub device_limit: u8,

    /// Максимальная скорость тарифа.
    ///
    /// 0 для Unlimited можно трактовать
    /// как отсутствие лимита.
    pub max_mbps: u32,
}

// =============================================================
// SIGNED TOKEN
// =============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionToken {
    pub claims: SubscriptionClaims,

    pub signature: [u8; SIGNATURE_SIZE],
}

impl SubscriptionClaims {
    /// Создаёт бинарную часть,
    /// которую подписывает Ed25519.
    pub fn encode_payload(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(TOKEN_PAYLOAD_SIZE);

        // BYTE 0-3
        buffer.extend_from_slice(&TOKEN_MAGIC);

        // BYTE 4
        buffer.put_u8(TOKEN_VERSION);

        // BYTE 5-8
        buffer.put_u32(self.key_id);

        // BYTE 9-24
        buffer.extend_from_slice(&self.token_id);

        // BYTE 25-40
        buffer.extend_from_slice(&self.client_id);

        // BYTE 41-48
        buffer.put_u64(self.issued_at);

        // BYTE 49-56
        buffer.put_u64(self.not_before);

        // BYTE 57-64
        buffer.put_u64(self.expires_at);

        // BYTE 65
        buffer.put_u8(self.plan as u8);

        // BYTE 66
        buffer.put_u8(self.device_limit);

        // BYTE 67-70
        buffer.put_u32(self.max_mbps);

        debug_assert_eq!(buffer.len(), TOKEN_PAYLOAD_SIZE);

        buffer.freeze()
    }
}

impl SubscriptionToken {
    /// Выпускает подписанный token.
    ///
    /// ЭТОТ метод вызывается только
    /// backend/admin частью PAYPHONE.
    ///
    /// Никогда не клиентом.
    pub fn sign(claims: SubscriptionClaims, signing_key: &SigningKey) -> Self {
        let payload = claims.encode_payload();

        let signature: Signature = signing_key.sign(&payload);

        Self {
            claims,

            signature: signature.to_bytes(),
        }
    }

    /// Проверяет Ed25519 signature.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), AuthError> {
        let payload = self.claims.encode_payload();

        let signature = Signature::from_bytes(&self.signature);

        verifying_key
            .verify(&payload, &signature)
            .map_err(|_| AuthError::InvalidSignature)
    }

    /// Token -> 135 bytes.
    pub fn encode(&self) -> Bytes {
        let payload = self.claims.encode_payload();

        let mut buffer = BytesMut::with_capacity(TOKEN_SIZE);

        buffer.extend_from_slice(&payload);

        buffer.extend_from_slice(&self.signature);

        debug_assert_eq!(buffer.len(), TOKEN_SIZE);

        buffer.freeze()
    }

    /// 135 bytes -> SubscriptionToken.
    ///
    /// ВАЖНО:
    ///
    /// decode() НЕ означает,
    /// что token настоящий.
    ///
    /// decode только разбирает bytes.
    ///
    /// Потом обязательно:
    ///
    /// verify()
    pub fn decode(mut buffer: Bytes) -> Result<Self, AuthError> {
        if buffer.len() != TOKEN_SIZE {
            return Err(AuthError::InvalidTokenLength);
        }

        // MAGIC
        let mut magic = [0u8; 4];

        buffer.copy_to_slice(&mut magic);

        if magic != TOKEN_MAGIC {
            return Err(AuthError::InvalidMagic);
        }

        // VERSION
        let version = buffer.get_u8();

        if version != TOKEN_VERSION {
            return Err(AuthError::UnsupportedTokenVersion(version));
        }

        let key_id = buffer.get_u32();

        let mut token_id = [0u8; TOKEN_ID_SIZE];

        buffer.copy_to_slice(&mut token_id);

        let mut client_id = [0u8; CLIENT_ID_SIZE];

        buffer.copy_to_slice(&mut client_id);

        let issued_at = buffer.get_u64();

        let not_before = buffer.get_u64();

        let expires_at = buffer.get_u64();

        let plan = SubscriptionPlan::try_from(buffer.get_u8())?;

        let device_limit = buffer.get_u8();

        let max_mbps = buffer.get_u32();

        let mut signature = [0u8; SIGNATURE_SIZE];

        buffer.copy_to_slice(&mut signature);

        Ok(Self {
            claims: SubscriptionClaims {
                key_id,
                token_id,
                client_id,
                issued_at,
                not_before,
                expires_at,
                plan,
                device_limit,
                max_mbps,
            },

            signature,
        })
    }
}

// =============================================================
// ERRORS
// =============================================================

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid subscription token length")]
    InvalidTokenLength,

    #[error("invalid subscription token magic")]
    InvalidMagic,

    #[error("unsupported token version: {0}")]
    UnsupportedTokenVersion(u8),

    #[error("unknown subscription plan: {0}")]
    UnknownPlan(u8),

    #[error("invalid subscription token signature")]
    InvalidSignature,

    #[error("unknown signing key id: {0}")]
    UnknownKeyId(u32),

    #[error("subscription token is not active yet")]
    NotYetValid,

    #[error("subscription token expired")]
    Expired,

    #[error("subscription token was issued in the future")]
    IssuedInFuture,

    #[error("subscription token is revoked")]
    Revoked,

    #[error("invalid token time range")]
    InvalidTimeRange,
}
