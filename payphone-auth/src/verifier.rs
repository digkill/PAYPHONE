use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{AuthError, SubscriptionClaims, SubscriptionToken, TOKEN_ID_SIZE, VerificationKeyRing};

/// Максимальная допустимая разница часов.
///
/// Например сервер показывает
/// 12:00:05,
/// issuer подписал token в 12:00:10.
///
/// 5 секунд нормально.
///
/// Ставим 5 минут.
pub const CLOCK_SKEW_SECONDS: u64 = 300;

/// Revocation store.
///
/// Production реализация позже
/// будет Redis/PostgreSQL.
///
/// Этот интерфейс оставляем
/// уже сейчас.
pub trait RevocationStore: Send + Sync {
    fn is_revoked(&self, token_id: &[u8; TOKEN_ID_SIZE]) -> bool;
}

// =============================================================
// MEMORY REVOCATION STORE
// =============================================================

pub struct MemoryRevocationStore {
    revoked: HashSet<[u8; TOKEN_ID_SIZE]>,
}

impl MemoryRevocationStore {
    pub fn new() -> Self {
        Self {
            revoked: HashSet::new(),
        }
    }

    pub fn revoke(&mut self, token_id: [u8; TOKEN_ID_SIZE]) {
        self.revoked.insert(token_id);
    }
}

impl Default for MemoryRevocationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationStore for MemoryRevocationStore {
    fn is_revoked(&self, token_id: &[u8; TOKEN_ID_SIZE]) -> bool {
        self.revoked.contains(token_id)
    }
}

// =============================================================
// AUTH VERIFIER
// =============================================================

pub struct SubscriptionVerifier<R>
where
    R: RevocationStore,
{
    keys: VerificationKeyRing,

    revocations: R,
}

impl<R> SubscriptionVerifier<R>
where
    R: RevocationStore,
{
    pub fn new(keys: VerificationKeyRing, revocations: R) -> Self {
        Self { keys, revocations }
    }

    /// Полная проверка token.
    ///
    /// Порядок важен:
    ///
    /// 1. key_id
    /// 2. signature
    /// 3. временные claims
    /// 4. revocation
    pub fn verify(&self, token: &SubscriptionToken) -> Result<SubscriptionClaims, AuthError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is before unix epoch")
            .as_secs();

        self.verify_at(token, now)
    }

    /// Отдельная версия с явно
    /// переданным timestamp.
    ///
    /// Очень полезно для тестов.
    pub fn verify_at(
        &self,
        token: &SubscriptionToken,

        now: u64,
    ) -> Result<SubscriptionClaims, AuthError> {
        let claims = &token.claims;

        //
        // Сначала опять signature.
        //
        // verify_at можно вызывать напрямую,
        // поэтому проверку не пропускаем.
        //
        let verifying_key = self.keys.get(claims.key_id)?;

        token.verify_signature(verifying_key)?;

        //
        // expires_at обязан быть
        // позже начала действия.
        //
        if claims.expires_at <= claims.not_before {
            return Err(AuthError::InvalidTimeRange);
        }

        //
        // issued_at не должен
        // сильно находиться в будущем.
        //
        if claims.issued_at > now.saturating_add(CLOCK_SKEW_SECONDS) {
            return Err(AuthError::IssuedInFuture);
        }

        //
        // Ещё не началась подписка.
        //
        if now.saturating_add(CLOCK_SKEW_SECONDS) < claims.not_before {
            return Err(AuthError::NotYetValid);
        }

        //
        // Подписка закончилась.
        //
        if now >= claims.expires_at {
            return Err(AuthError::Expired);
        }

        //
        // Token отозван вручную.
        //
        if self.revocations.is_revoked(&claims.token_id) {
            return Err(AuthError::Revoked);
        }

        //
        // Возвращаем уже ПРОВЕРЕННЫЕ claims.
        //
        Ok(claims.clone())
    }
}
