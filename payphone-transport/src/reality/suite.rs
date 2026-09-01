//! TLS 1.3 cipher suites on the REALITY path (AES-128, AES-256, ChaCha20).

use std::io;

use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use chacha20poly1305::ChaCha20Poly1305;
use sha2::{Digest, Sha256, Sha384};

use super::auth::hmac_sha256;

pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl Suite {
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            TLS_AES_128_GCM_SHA256 => Some(Self::Aes128GcmSha256),
            TLS_AES_256_GCM_SHA384 => Some(Self::Aes256GcmSha384),
            TLS_CHACHA20_POLY1305_SHA256 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    pub fn hash_len(self) -> usize {
        match self {
            Self::Aes256GcmSha384 => 48,
            _ => 32,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            _ => 32,
        }
    }

    fn sha384(self) -> bool {
        matches!(self, Self::Aes256GcmSha384)
    }
}

pub struct Transcript {
    suite: Suite,
    sha256: Sha256,
    sha384: Sha384,
}

impl Transcript {
    pub fn new(suite: Suite) -> Self {
        Self {
            suite,
            sha256: Sha256::new(),
            sha384: Sha384::new(),
        }
    }

    pub fn update(&mut self, handshake: &[u8]) {
        if self.suite.sha384() {
            self.sha384.update(handshake);
        } else {
            self.sha256.update(handshake);
        }
    }

    pub fn hash(&self) -> Vec<u8> {
        if self.suite.sha384() {
            self.sha384.clone().finalize().to_vec()
        } else {
            self.sha256.clone().finalize().to_vec()
        }
    }
}

pub struct TrafficKeys {
    suite: Suite,
    key: Vec<u8>,
    iv: [u8; 12],
    pub seq: u64,
}

pub struct HsKeys {
    pub keys: TrafficKeys,
    pub secret: Vec<u8>,
}

pub fn handshake_traffic_keys(
    suite: Suite,
    shared: &[u8; 32],
    hello_hash: &[u8],
) -> (HsKeys, HsKeys, Vec<u8>) {
    let hash_len = suite.hash_len();
    let zeros = vec![0u8; hash_len];
    let early = hmac(suite, &zeros, &zeros);
    let empty = hash_empty(suite);
    let derived = derive_secret(suite, &early, b"derived", &empty);
    let handshake_secret = hmac(suite, &derived, shared);
    let client_secret = derive_secret(suite, &handshake_secret, b"c hs traffic", hello_hash);
    let server_secret = derive_secret(suite, &handshake_secret, b"s hs traffic", hello_hash);

    (
        HsKeys {
            keys: traffic_keys(suite, &client_secret),
            secret: client_secret,
        },
        HsKeys {
            keys: traffic_keys(suite, &server_secret),
            secret: server_secret,
        },
        handshake_secret,
    )
}

pub fn application_traffic_keys(
    suite: Suite,
    handshake_secret: &[u8],
    hash: &[u8],
) -> (TrafficKeys, TrafficKeys) {
    let empty = hash_empty(suite);
    let derived = derive_secret(suite, handshake_secret, b"derived", &empty);
    let zeros = vec![0u8; suite.hash_len()];
    let master = hmac(suite, &derived, &zeros);
    let client = derive_secret(suite, &master, b"c ap traffic", hash);
    let server = derive_secret(suite, &master, b"s ap traffic", hash);
    (traffic_keys(suite, &client), traffic_keys(suite, &server))
}

fn traffic_keys(suite: Suite, secret: &[u8]) -> TrafficKeys {
    let key = hkdf_expand_label(suite, secret, b"key", b"", suite.key_len());
    let iv_bytes = hkdf_expand_label(suite, secret, b"iv", b"", 12);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);
    TrafficKeys {
        suite,
        key,
        iv,
        seq: 0,
    }
}

pub fn finished_verify(suite: Suite, base_secret: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let finished_key = hkdf_expand_label(suite, base_secret, b"finished", b"", suite.hash_len());
    hmac(suite, &finished_key, transcript_hash)
}

fn derive_secret(suite: Suite, secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    hkdf_expand_label(suite, secret, label, transcript_hash, suite.hash_len())
}

fn hkdf_expand_label(
    suite: Suite,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    hkdf_label.push((6 + label.len()) as u8);
    hkdf_label.extend_from_slice(b"tls13 ");
    hkdf_label.extend_from_slice(label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    let mut out = vec![0u8; length];
    hkdf_expand(suite, secret, &hkdf_label, &mut out);
    out
}

fn hkdf_expand(suite: Suite, prk: &[u8], info: &[u8], okm: &mut [u8]) {
    let mut previous = Vec::new();
    let mut offset = 0;
    let mut counter = 1u8;

    while offset < okm.len() {
        let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter);
        previous = hmac(suite, prk, &input);
        let take = (okm.len() - offset).min(previous.len());
        okm[offset..offset + take].copy_from_slice(&previous[..take]);
        offset += take;
        counter = counter.checked_add(1).expect("hkdf counter");
    }
}

fn hash_empty(suite: Suite) -> Vec<u8> {
    if suite.sha384() {
        Sha384::digest(b"").to_vec()
    } else {
        Sha256::digest(b"").to_vec()
    }
}

fn hmac(suite: Suite, key: &[u8], data: &[u8]) -> Vec<u8> {
    if suite.sha384() {
        hmac_sha384(key, data).to_vec()
    } else {
        hmac_sha256(key, data).to_vec()
    }
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    const BLOCK: usize = 128;
    let mut key_block = [0u8; BLOCK];

    if key.len() > BLOCK {
        let hashed = Sha384::digest(key);
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

    let mut inner = Sha384::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha384::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq[i];
    }
    nonce
}

pub fn encrypt_app(keys: &TrafficKeys, inner_type: u8, plaintext: &[u8]) -> Vec<u8> {
    encrypt_app_padded(keys, inner_type, plaintext, None)
}

/// `pad_to_record` is the full TLS record length (header + ciphertext), matching dest.
pub fn encrypt_app_padded(
    keys: &TrafficKeys,
    inner_type: u8,
    plaintext: &[u8],
    pad_to_record: Option<usize>,
) -> Vec<u8> {
    let mut inner = Vec::with_capacity(plaintext.len() + 1);
    inner.extend_from_slice(plaintext);
    inner.push(inner_type);
    if let Some(target) = pad_to_record {
        let min_record = 5 + inner.len() + 16;
        if target > min_record {
            inner.resize(target - 5 - 16, 0);
        }
    }
    let ct_len = inner.len() + 16;
    let header = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];
    let nonce = nonce(&keys.iv, keys.seq);
    let sealed = aead_seal(keys.suite, &keys.key, &nonce, &header, &inner);
    let mut record = header.to_vec();
    record.extend_from_slice(&sealed);
    record
}

pub fn decrypt_app(keys: &TrafficKeys, body: &[u8]) -> io::Result<(u8, Vec<u8>)> {
    let ct_len = body.len();
    let header = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];
    let nonce = nonce(&keys.iv, keys.seq);
    let plain = aead_open(keys.suite, &keys.key, &nonce, &header, body)?;
    split_inner(plain)
}

fn aead_seal(suite: Suite, key: &[u8], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Vec<u8> {
    let payload = Payload { msg, aad };
    match suite {
        Suite::Aes128GcmSha256 => Aes128Gcm::new_from_slice(key)
            .expect("aes-128")
            .encrypt(aes_gcm::Nonce::from_slice(nonce), payload)
            .expect("encrypt"),
        Suite::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
            .expect("aes-256")
            .encrypt(aes_gcm::Nonce::from_slice(nonce), payload)
            .expect("encrypt"),
        Suite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(key)
            .expect("chacha")
            .encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            .expect("encrypt"),
    }
}

fn aead_open(
    suite: Suite,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    msg: &[u8],
) -> io::Result<Vec<u8>> {
    let payload = Payload { msg, aad };
    let result = match suite {
        Suite::Aes128GcmSha256 => Aes128Gcm::new_from_slice(key)
            .map_err(|error| io::Error::other(error.to_string()))?
            .decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
        Suite::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
            .map_err(|error| io::Error::other(error.to_string()))?
            .decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
        Suite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(key)
            .map_err(|error| io::Error::other(error.to_string()))?
            .decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload),
    };
    result.map_err(|_| io::Error::other("tls decrypt failed"))
}

fn split_inner(mut plain: Vec<u8>) -> io::Result<(u8, Vec<u8>)> {
    while plain.last() == Some(&0) {
        plain.pop();
    }

    let typ = plain
        .pop()
        .ok_or_else(|| io::Error::other("empty tls inner plaintext"))?;

    Ok((typ, plain))
}

impl TrafficKeys {
    pub fn encrypt(&mut self, inner_type: u8, plaintext: &[u8]) -> Vec<u8> {
        self.encrypt_padded(inner_type, plaintext, None)
    }

    pub fn encrypt_padded(
        &mut self,
        inner_type: u8,
        plaintext: &[u8],
        pad_to_record: Option<usize>,
    ) -> Vec<u8> {
        let record = encrypt_app_padded(self, inner_type, plaintext, pad_to_record);
        self.seq += 1;
        record
    }

    pub fn decrypt(&mut self, body: &[u8]) -> io::Result<(u8, Vec<u8>)> {
        let out = decrypt_app(self, body)?;
        self.seq += 1;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_record_hits_dest_length() {
        let keys = traffic_keys(Suite::Aes128GcmSha256, &[0x11u8; 32]);
        let record = encrypt_app_padded(&keys, 0x16, b"hello", Some(600));
        assert_eq!(record.len(), 600);
        assert_eq!(record[0], 0x17);
        let (inner, content) = decrypt_app(&keys, &record[5..]).unwrap();
        assert_eq!(inner, 0x16);
        assert_eq!(content, b"hello");
    }
}
