use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
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
/// `FileRevocationStore` is the on-disk implementation the server uses.
/// Redis/PostgreSQL can still sit behind this trait later.
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
// FILE REVOCATION STORE
// =============================================================

/// One hex token_id per line. Missing file = empty set. Re-reads when mtime changes.
pub struct FileRevocationStore {
    path: PathBuf,
    cache: Mutex<(Option<SystemTime>, HashSet<[u8; TOKEN_ID_SIZE]>)>,
}

impl FileRevocationStore {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cache: Mutex::new((None, HashSet::new())),
        }
    }
}

impl RevocationStore for FileRevocationStore {
    fn is_revoked(&self, token_id: &[u8; TOKEN_ID_SIZE]) -> bool {
        let mtime = fs::metadata(&self.path)
            .and_then(|meta| meta.modified())
            .ok();
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());

        if cache.0 != mtime {
            cache.1 = load_revoked_ids(&self.path);
            cache.0 = mtime;
        }

        cache.1.contains(token_id)
    }
}

pub fn load_revoked_ids(path: &Path) -> HashSet<[u8; TOKEN_ID_SIZE]> {
    let Ok(text) = fs::read_to_string(path) else {
        return HashSet::new();
    };

    text.lines().filter_map(parse_token_id_hex).collect()
}

pub fn append_revoked_id(path: &Path, token_id: [u8; TOKEN_ID_SIZE]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let hex = token_id_hex(&token_id);
    let existing = load_revoked_ids(path);

    if existing.contains(&token_id) {
        return Ok(());
    }

    let mut text = fs::read_to_string(path).unwrap_or_default();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&hex);
    text.push('\n');
    fs::write(path, text)
}

pub fn token_id_hex(token_id: &[u8; TOKEN_ID_SIZE]) -> String {
    token_id.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn parse_token_id_hex(line: &str) -> Option<[u8; TOKEN_ID_SIZE]> {
    let hex = line.trim().trim_start_matches("0x");
    if hex.len() != TOKEN_ID_SIZE * 2 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }

    let mut id = [0u8; TOKEN_ID_SIZE];
    for (i, slot) in id.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(id)
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
