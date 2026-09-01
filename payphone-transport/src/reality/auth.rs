use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn x25519_public(private: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private);
    PublicKey::from(&secret).to_bytes()
}

pub fn x25519_shared(private: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private);
    let peer = PublicKey::from(*peer);
    secret.diffie_hellman(&peer).to_bytes()
}

pub fn reality_auth_key(shared: &[u8; 32], hello_random: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    hkdf_sha256(shared, &hello_random[..20], b"REALITY", &mut key);
    key
}

pub fn session_id_plain(version: [u8; 3], unix_secs: u32, short_id: [u8; 8]) -> [u8; 16] {
    let mut plain = [0u8; 16];
    plain[..3].copy_from_slice(&version);
    plain[4..8].copy_from_slice(&unix_secs.to_be_bytes());
    plain[8..16].copy_from_slice(&short_id);
    plain
}

/// Encrypt the 16-byte session_id field. `handshake` must already contain
/// zeros at the session_id bytes (offset 39), matching Xray's AAD.
pub fn seal_session_id(
    client_private: &[u8; 32],
    server_public: &[u8; 32],
    hello_random: &[u8; 32],
    plain: &[u8; 16],
    handshake: &[u8],
) -> [u8; 32] {
    let shared = x25519_shared(client_private, server_public);
    let key = reality_auth_key(&shared, hello_random);
    aes_gcm_seal(&key, &hello_random[20..32], handshake, plain)
}

pub fn open_session_id(
    server_private: &[u8; 32],
    client_public: &[u8; 32],
    hello_random: &[u8; 32],
    sealed: &[u8],
    handshake: &[u8],
) -> Option<[u8; 16]> {
    if sealed.len() != 32 {
        return None;
    }

    let mut aad = handshake.to_vec();

    if aad.len() < 71 {
        return None;
    }

    aad[39..71].fill(0);

    let shared = x25519_shared(server_private, client_public);
    let key = reality_auth_key(&shared, hello_random);
    let plain = aes_gcm_open(&key, &hello_random[20..32], &aad, sealed)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&plain);
    Some(out)
}

pub fn aes_gcm_seal(key: &[u8; 32], nonce_12: &[u8], aad: &[u8], plain: &[u8; 16]) -> [u8; 32] {
    let cipher = Aes256Gcm::new_from_slice(key).expect("aes-256 key");
    let nonce = aes_gcm::Nonce::from_slice(nonce_12);
    let sealed = cipher
        .encrypt(nonce, Payload { msg: plain, aad })
        .expect("aes-gcm seal");

    let mut out = [0u8; 32];
    out.copy_from_slice(&sealed);
    out
}

fn aes_gcm_open(key: &[u8; 32], nonce_12: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = aes_gcm::Nonce::from_slice(nonce_12);
    cipher.decrypt(nonce, Payload { msg: sealed, aad }).ok()
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) {
    let prk = hmac_sha256(salt, ikm);
    hkdf_expand(&prk, info, okm);
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], okm: &mut [u8]) {
    let mut previous = Vec::new();
    let mut offset = 0;
    let mut counter = 1u8;

    while offset < okm.len() {
        let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter);
        previous = hmac_sha256(prk, &input).to_vec();
        let take = (okm.len() - offset).min(previous.len());
        okm[offset..offset + take].copy_from_slice(&previous[..take]);
        offset += take;
        counter = counter.checked_add(1).expect("hkdf counter");
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];

    if key.len() > BLOCK {
        let hashed = Sha256::digest(key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];

    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    const BLOCK: usize = 128;
    let mut key_block = [0u8; BLOCK];

    if key.len() > BLOCK {
        let hashed = Sha512::digest(key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];

    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha512::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
