use std::{
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use rand_core::{OsRng, TryRngCore};
use sha2::{Digest, Sha256};

use payphone_core::all_good_dude::{SERVER_NONCE_SIZE, SESSION_ID_SIZE};

const MAGIC: &[u8; 4] = b"PAYE";

const VERSION: u8 = 1;

const NONCE_SIZE: usize = 12;

const PLAINTEXT_SIZE: usize = SESSION_ID_SIZE + SERVER_NONCE_SIZE;

const TAG_SIZE: usize = 16;

pub struct SavedSession {
    pub session_id: [u8; SESSION_ID_SIZE],

    pub resume_token: [u8; SERVER_NONCE_SIZE],
}

struct SessionStore {
    path: PathBuf,

    key: [u8; 32],
}

static STORE: OnceLock<SessionStore> = OnceLock::new();

pub fn init(path: PathBuf, psk: &str) {
    let _ = STORE.set(SessionStore {
        path,
        key: derive_key(psk),
    });
}

fn store() -> &'static SessionStore {
    STORE.get().expect("session store is not initialized")
}

pub fn path() -> &'static Path {
    &store().path
}

pub fn exists() -> bool {
    path().exists()
}

pub fn save(
    session_id: [u8; SESSION_ID_SIZE],
    resume_token: [u8; SERVER_NONCE_SIZE],
) -> std::io::Result<()> {
    let mut plaintext = [0u8; PLAINTEXT_SIZE];

    plaintext[..SESSION_ID_SIZE].copy_from_slice(&session_id);

    plaintext[SESSION_ID_SIZE..].copy_from_slice(&resume_token);

    let bytes = seal(&store().key, &plaintext).map_err(|error| std::io::Error::other(error))?;

    fs::write(path(), bytes)
}

pub fn load() -> Option<SavedSession> {
    let data = fs::read(path()).ok()?;

    let plaintext = open(&store().key, &data)?;

    let mut session_id = [0u8; SESSION_ID_SIZE];

    session_id.copy_from_slice(&plaintext[..SESSION_ID_SIZE]);

    let mut resume_token = [0u8; SERVER_NONCE_SIZE];

    resume_token.copy_from_slice(&plaintext[SESSION_ID_SIZE..]);

    Some(SavedSession {
        session_id,
        resume_token,
    })
}

pub fn forget() {
    let _ = fs::remove_file(path());
}

fn derive_key(psk: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(b"payphone-session-v1");

    hasher.update(psk.as_bytes());

    hasher.finalize().into()
}

fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| "bad session key")?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];

    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| "rng failed")?;

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| "session encrypt failed")?;

    let mut out = Vec::with_capacity(4 + 1 + NONCE_SIZE + ciphertext.len());

    out.extend_from_slice(MAGIC);

    out.push(VERSION);

    out.extend_from_slice(&nonce_bytes);

    out.extend_from_slice(&ciphertext);

    Ok(out)
}

fn open(key: &[u8; 32], data: &[u8]) -> Option<[u8; PLAINTEXT_SIZE]> {
    if data.len() == PLAINTEXT_SIZE {
        let mut plaintext = [0u8; PLAINTEXT_SIZE];

        plaintext.copy_from_slice(data);

        return Some(plaintext);
    }

    if data.len() < 4 + 1 + NONCE_SIZE + TAG_SIZE || data[..4] != *MAGIC || data[4] != VERSION {
        return None;
    }

    let nonce = Nonce::from_slice(&data[5..5 + NONCE_SIZE]);

    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;

    let plaintext = cipher.decrypt(nonce, &data[5 + NONCE_SIZE..]).ok()?;

    if plaintext.len() != PLAINTEXT_SIZE {
        return None;
    }

    let mut out = [0u8; PLAINTEXT_SIZE];

    out.copy_from_slice(&plaintext);

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_roundtrip() {
        let key = derive_key("test-psk-not-a-placeholder");

        let mut plaintext = [0u8; PLAINTEXT_SIZE];

        plaintext[0] = 7;

        plaintext[47] = 9;

        let sealed = seal(&key, &plaintext).unwrap();

        assert_ne!(&sealed[5 + NONCE_SIZE..], plaintext.as_slice());

        assert_eq!(open(&key, &sealed).unwrap(), plaintext);
    }

    #[test]
    fn plaintext_legacy_still_loads() {
        let key = derive_key("test-psk-not-a-placeholder");

        let plaintext = [3u8; PLAINTEXT_SIZE];

        assert_eq!(open(&key, &plaintext).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let mut plaintext = [1u8; PLAINTEXT_SIZE];

        plaintext[2] = 4;

        let sealed = seal(&derive_key("one"), &plaintext).unwrap();

        assert!(open(&derive_key("two"), &sealed).is_none());
    }
}
