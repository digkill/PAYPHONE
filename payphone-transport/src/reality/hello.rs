//! TLS 1.3 ClientHello parse/build. Session-id sits at handshake offset 39.
//!
//! The builder follows uTLS `HelloChrome_131`: GREASE first/last stay pinned
//! (`ShuffleChromeTLSExtensions` skips GREASE), middle extensions including
//! GREASE ECH are shuffled, ALPN h2+http/1.1, X25519MLKEM768 + X25519.
//! GREASE/ECH/ML-KEM bytes are random, so this is not bit-identical to a
//! given Chrome capture — Chrome itself is not bit-stable month to month.
//! Signature algorithms match Chrome (no ed25519) — the VPN server is a
//! custom TLS 1.3 stack that still signs CertificateVerify with Ed25519.
//! X25519MLKEM768 carries a real FIPS 203 ML-KEM-768 public key; the VPN
//! still finishes with X25519 (last 32 bytes of the hybrid share).

use rand_core::{OsRng, TryRngCore};

pub const SESSION_ID_OFFSET: usize = 39;
pub const SESSION_ID_LEN: usize = 32;

const EXT_SERVER_NAME: u16 = 0;
const EXT_STATUS_REQUEST: u16 = 5;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SCT: u16 = 18;
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
const EXT_COMPRESS_CERTIFICATE: u16 = 27;
const EXT_SESSION_TICKET: u16 = 35;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_KEY_SHARE: u16 = 51;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
const EXT_ALPS: u16 = 17513;
const EXT_ECH: u16 = 0xfe0d;

const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

const MLKEM768_PUBLIC_LEN: usize = 1184;
const HPKE_KDF_SHA256: u16 = 0x0001;
const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;

const GREASE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

#[derive(Clone, Debug)]
pub struct ClientHelloView {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub sni: Option<String>,
    pub x25519_public: Option<[u8; 32]>,
    pub alpn: Vec<Vec<u8>>,
}

impl ClientHelloView {
    pub fn parse(record: &[u8]) -> Option<Self> {
        let handshake = handshake_from_record(record)?;
        parse_handshake(handshake)
    }

    /// Xray dest-probe class: 0 = no ALPN, 1 = http/1.1, 2 = h2.
    pub fn alpn_class(&self) -> u8 {
        match self.alpn.first().map(Vec::as_slice) {
            None => 0,
            Some(b"h2") => 2,
            Some(_) => 1,
        }
    }

    pub fn has_acme_alpn(&self) -> bool {
        self.alpn
            .iter()
            .any(|proto| proto.as_slice() == b"acme-tls/1")
    }
}

pub fn handshake_from_record(record: &[u8]) -> Option<&[u8]> {
    if record.len() < 5 || record[0] != 0x16 {
        return None;
    }

    let len = u16::from_be_bytes([record[3], record[4]]) as usize;

    if record.len() < 5 + len {
        return None;
    }

    Some(&record[5..5 + len])
}

fn parse_handshake(handshake: &[u8]) -> Option<ClientHelloView> {
    if handshake.len() < 42 || handshake[0] != 0x01 {
        return None;
    }

    let body_len = u24(&handshake[1..4])?;

    if handshake.len() < 4 + body_len {
        return None;
    }

    let body = &handshake[4..4 + body_len];
    let mut i = 0usize;

    i += 2;
    let random: [u8; 32] = body.get(i..i + 32)?.try_into().ok()?;
    i += 32;

    let sid_len = *body.get(i)? as usize;
    i += 1;
    let session_id = body.get(i..i + sid_len)?.to_vec();
    i += sid_len;

    let cs_len = u16::from_be_bytes(body.get(i..i + 2)?.try_into().ok()?) as usize;
    i += 2 + cs_len;

    let comp_len = *body.get(i)? as usize;
    i += 1 + comp_len;

    let ext_len = u16::from_be_bytes(body.get(i..i + 2)?.try_into().ok()?) as usize;
    i += 2;
    let exts = body.get(i..i + ext_len)?;

    let (sni, x25519_public, alpn) = parse_extensions(exts)?;

    Some(ClientHelloView {
        random,
        session_id,
        sni,
        x25519_public,
        alpn,
    })
}

fn parse_extensions(mut exts: &[u8]) -> Option<(Option<String>, Option<[u8; 32]>, Vec<Vec<u8>>)> {
    let mut sni = None;
    let mut x25519 = None;
    let mut alpn = Vec::new();

    while exts.len() >= 4 {
        let typ = u16::from_be_bytes(exts[0..2].try_into().ok()?);
        let len = u16::from_be_bytes(exts[2..4].try_into().ok()?) as usize;
        let data = exts.get(4..4 + len)?;
        exts = &exts[4 + len..];

        match typ {
            EXT_SERVER_NAME => sni = parse_sni(data),
            EXT_KEY_SHARE => x25519 = parse_x25519_share(data),
            EXT_ALPN => alpn = parse_alpn(data),
            _ => {}
        }
    }

    Some((sni, x25519, alpn))
}

fn parse_alpn(data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() < 2 {
        return Vec::new();
    }

    let list_len = u16::from_be_bytes(data[0..2].try_into().unwrap_or([0, 0])) as usize;
    let Some(mut list) = data.get(2..2 + list_len) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    while !list.is_empty() {
        let n = usize::from(list[0]);
        if list.len() < 1 + n {
            break;
        }
        out.push(list[1..1 + n].to_vec());
        list = &list[1 + n..];
    }
    out
}

fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    let list_len = u16::from_be_bytes(data[0..2].try_into().ok()?) as usize;
    let list = data.get(2..2 + list_len)?;

    if list.first().copied() != Some(0) {
        return None;
    }

    let name_len = u16::from_be_bytes(list.get(1..3)?.try_into().ok()?) as usize;
    let name = list.get(3..3 + name_len)?;
    String::from_utf8(name.to_vec()).ok()
}

fn parse_x25519_share(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes(data[0..2].try_into().ok()?) as usize;
    let mut shares = data.get(2..2 + list_len)?;

    while shares.len() >= 4 {
        let group = u16::from_be_bytes(shares[0..2].try_into().ok()?);
        let key_len = u16::from_be_bytes(shares[2..4].try_into().ok()?) as usize;
        let key = shares.get(4..4 + key_len)?;
        shares = &shares[4 + key_len..];

        if group == GROUP_X25519 && key.len() == 32 {
            return key.try_into().ok();
        }

        // X25519MLKEM768: last 32 bytes are the X25519 public.
        if group == GROUP_X25519_MLKEM768 && key.len() >= 32 {
            return key[key.len() - 32..].try_into().ok();
        }
    }

    None
}

#[allow(dead_code)]
pub fn build_client_hello_record(
    random: &[u8; 32],
    session_id: &[u8; 32],
    sni: &str,
    x25519_public: &[u8; 32],
) -> Vec<u8> {
    let handshake = build_client_hello_handshake(random, session_id, sni, x25519_public);
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(0x16);
    record.extend_from_slice(&0x0301u16.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

pub fn build_client_hello_handshake(
    random: &[u8; 32],
    session_id: &[u8; 32],
    sni: &str,
    x25519_public: &[u8; 32],
) -> Vec<u8> {
    let grease = grease_pair();
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(random);
    body.push(SESSION_ID_LEN as u8);
    body.extend_from_slice(session_id);

    let ciphers = chrome_ciphers(grease.0);
    body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for suite in ciphers {
        body.extend_from_slice(&suite.to_be_bytes());
    }

    body.push(1);
    body.push(0);

    let extensions = encode_extensions(sni, x25519_public, grease);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::with_capacity(4 + body.len());
    handshake.push(0x01);
    handshake.extend_from_slice(&u24_bytes(body.len()));
    handshake.extend_from_slice(&body);
    handshake
}

fn chrome_ciphers(grease: u16) -> [u16; 16] {
    [
        grease,
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        0xc02b,
        0xc02f,
        0xc02c,
        0xc030,
        0xcca9,
        0xcca8,
        0xc013,
        0xc014,
        0x009c,
        0x009d,
        0x002f,
        0x0035,
    ]
}

fn encode_extensions(sni: &str, x25519_public: &[u8; 32], grease: (u16, u16)) -> Vec<u8> {
    let (g0, g1) = grease;
    let mut middle = vec![
        ext(EXT_SERVER_NAME, &sni_payload(sni)),
        ext(EXT_EXTENDED_MASTER_SECRET, &[]),
        ext(EXT_RENEGOTIATION_INFO, &[0]),
        ext(
            EXT_SUPPORTED_GROUPS,
            &u16_list(&[
                g0,
                GROUP_X25519_MLKEM768,
                GROUP_X25519,
                GROUP_SECP256R1,
                GROUP_SECP384R1,
            ]),
        ),
        ext(EXT_EC_POINT_FORMATS, &[1, 0]),
        ext(EXT_SESSION_TICKET, &[]),
        ext(EXT_ALPN, &alpn_h2_http11()),
        ext(EXT_STATUS_REQUEST, &[1, 0, 0, 0, 0]),
        ext(
            EXT_SIGNATURE_ALGORITHMS,
            &u16_list(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        ),
        ext(EXT_SCT, &[]),
        ext(EXT_KEY_SHARE, &key_share(g0, x25519_public)),
        ext(EXT_PSK_KEY_EXCHANGE_MODES, &[1, 1]),
        ext(EXT_SUPPORTED_VERSIONS, &supported_versions(g1)),
        ext(EXT_COMPRESS_CERTIFICATE, &[2, 0x00, 0x02]),
        ext(EXT_ALPS, &alpn_list(&[b"h2"])),
        // uTLS HelloChrome_131: BoringGREASEECH then trailing GREASE.
        // Shuffle pins GREASE; ECH may move in the middle.
        grease_ech(),
    ];

    shuffle_middle(&mut middle);

    let mut out = Vec::new();
    out.extend(ext(g0, &[0]));
    for item in middle {
        out.extend(item);
    }
    out.extend(ext(g1, &[0]));
    out
}

fn supported_versions(grease: u16) -> Vec<u8> {
    let mut payload = vec![6];
    payload.extend_from_slice(&grease.to_be_bytes());
    payload.extend_from_slice(&0x0304u16.to_be_bytes());
    payload.extend_from_slice(&0x0303u16.to_be_bytes());
    payload
}

fn sni_payload(sni: &str) -> Vec<u8> {
    let host = sni.as_bytes();
    let mut payload = Vec::with_capacity(5 + host.len());
    payload.extend_from_slice(&((3 + host.len()) as u16).to_be_bytes());
    payload.push(0);
    payload.extend_from_slice(&(host.len() as u16).to_be_bytes());
    payload.extend_from_slice(host);
    payload
}

fn alpn_h2_http11() -> Vec<u8> {
    alpn_list(&[b"h2", b"http/1.1"])
}

fn alpn_list(protos: &[&[u8]]) -> Vec<u8> {
    let inner: usize = protos.iter().map(|p| 1 + p.len()).sum();
    let mut payload = Vec::with_capacity(2 + inner);
    payload.extend_from_slice(&(inner as u16).to_be_bytes());
    for proto in protos {
        payload.push(proto.len() as u8);
        payload.extend_from_slice(proto);
    }
    payload
}

fn key_share(grease: u16, public: &[u8; 32]) -> Vec<u8> {
    let mut hybrid = Vec::with_capacity(MLKEM768_PUBLIC_LEN + 32);
    hybrid.extend_from_slice(&mlkem768_public());
    hybrid.extend_from_slice(public);

    let mut shares = Vec::new();
    shares.extend(key_share_entry(grease, &[0]));
    shares.extend(key_share_entry(GROUP_X25519_MLKEM768, &hybrid));
    shares.extend(key_share_entry(GROUP_X25519, public));

    let mut payload = Vec::with_capacity(2 + shares.len());
    payload.extend_from_slice(&(shares.len() as u16).to_be_bytes());
    payload.extend(shares);
    payload
}

fn mlkem768_public() -> [u8; MLKEM768_PUBLIC_LEN] {
    let mut seed = [0u8; 64];
    fill_random(&mut seed);
    *libcrux_ml_kem::mlkem768::generate_key_pair(seed).pk()
}

fn key_share_entry(group: u16, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + key.len());
    out.extend_from_slice(&group.to_be_bytes());
    out.extend_from_slice(&(key.len() as u16).to_be_bytes());
    out.extend_from_slice(key);
    out
}

fn grease_ech() -> Vec<u8> {
    let mut enc = [0u8; 32];
    fill_random(&mut enc);
    let payload_lens = [144u16, 176, 208, 240];
    let mut payload = vec![0u8; payload_lens[random_u8() as usize % payload_lens.len()] as usize];
    fill_random(&mut payload);
    let config_id = random_u8();

    let mut data = Vec::with_capacity(11 + enc.len() + payload.len());
    data.push(0);
    data.extend_from_slice(&HPKE_KDF_SHA256.to_be_bytes());
    data.extend_from_slice(&HPKE_AEAD_AES_128_GCM.to_be_bytes());
    data.push(config_id);
    data.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    data.extend_from_slice(&enc);
    data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    data.extend_from_slice(&payload);
    ext(EXT_ECH, &data)
}

fn u16_list(values: &[u16]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + values.len() * 2);
    payload.extend_from_slice(&((values.len() * 2) as u16).to_be_bytes());
    for value in values {
        payload.extend_from_slice(&value.to_be_bytes());
    }
    payload
}

fn ext(typ: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn grease_pair() -> (u16, u16) {
    let a = GREASE[random_u8() as usize % GREASE.len()];
    let mut b = GREASE[random_u8() as usize % GREASE.len()];
    if a == b {
        let i = GREASE.iter().position(|g| *g == a).unwrap_or(0);
        b = GREASE[(i + 8) % GREASE.len()];
    }
    (a, b)
}

fn shuffle_middle(exts: &mut [Vec<u8>]) {
    if exts.len() < 2 {
        return;
    }

    for i in (1..exts.len()).rev() {
        let j = (random_u8() as usize) % (i + 1);
        exts.swap(i, j);
    }
}

fn fill_random(buf: &mut [u8]) {
    OsRng.try_fill_bytes(buf).expect("os rng");
}

fn random_u8() -> u8 {
    let mut b = [0u8; 1];
    fill_random(&mut b);
    b[0]
}

fn u24(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 3 {
        return None;
    }

    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

fn u24_bytes(len: usize) -> [u8; 3] {
    [(len >> 16) as u8, (len >> 8) as u8, len as u8]
}

const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// TLS 1.3 ServerHello (handshake message, type 2). JA3S is cipher + extension order.
#[derive(Clone, Debug)]
pub struct ServerHelloView {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub x25519_public: Option<[u8; 32]>,
}

impl ServerHelloView {
    pub fn parse(msg: &[u8]) -> Option<Self> {
        if msg.len() < 6 || msg[0] != 2 {
            return None;
        }

        let body_len = u24(&msg[1..4])?;
        let body = msg.get(4..4 + body_len)?;
        let mut i = 2;
        let random: [u8; 32] = body.get(i..i + 32)?.try_into().ok()?;
        i += 32;

        if random == HRR_RANDOM {
            return None;
        }

        let sid_len = *body.get(i)? as usize;
        i += 1;
        let session_id = body.get(i..i + sid_len)?.to_vec();
        i += sid_len;
        let cipher = u16::from_be_bytes(body.get(i..i + 2)?.try_into().ok()?);
        i += 3;
        let ext_len = u16::from_be_bytes(body.get(i..i + 2)?.try_into().ok()?) as usize;
        i += 2;
        let mut exts = body.get(i..i + ext_len)?;
        let mut extensions = Vec::new();
        let mut x25519_public = None;

        while exts.len() >= 4 {
            let typ = u16::from_be_bytes(exts[0..2].try_into().ok()?);
            let len = u16::from_be_bytes(exts[2..4].try_into().ok()?) as usize;
            let data = exts.get(4..4 + len)?;
            exts = &exts[4 + len..];
            extensions.push(typ);

            if typ == EXT_KEY_SHARE {
                x25519_public = parse_server_share(data);
            }
        }

        Some(Self {
            random,
            session_id,
            cipher,
            extensions,
            x25519_public,
        })
    }

    /// JA3S: TLS version, cipher, ServerHello extension types.
    pub fn ja3s(&self) -> (u16, u16, Vec<u16>) {
        (0x0303, self.cipher, self.extensions.clone())
    }
}

fn parse_server_share(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 4 {
        return None;
    }

    let group = u16::from_be_bytes(data[0..2].try_into().ok()?);
    let len = u16::from_be_bytes(data[2..4].try_into().ok()?) as usize;
    let key = data.get(4..4 + len)?;

    if group == GROUP_X25519 && key.len() == 32 {
        return key.try_into().ok();
    }

    if group == GROUP_X25519_MLKEM768 && key.len() >= 32 {
        return key[key.len() - 32..].try_into().ok();
    }

    None
}

/// Overwrite dest's X25519 key_share in place (Xray REALITY). Cipher and
/// extension order stay dest's, so JA3S matches.
pub fn patch_server_hello_x25519(msg: &mut [u8], public: &[u8; 32]) -> bool {
    if msg.len() < 6 || msg[0] != 2 {
        return false;
    }

    let Some(body_len) = u24(&msg[1..4]) else {
        return false;
    };

    let Some(body) = msg.get_mut(4..4 + body_len) else {
        return false;
    };

    let mut i = 2 + 32;
    let Some(&sid_len) = body.get(i) else {
        return false;
    };
    i += 1 + sid_len as usize + 2 + 1;
    let Some(ext_len) = body
        .get(i..i + 2)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_be_bytes)
    else {
        return false;
    };
    i += 2;
    let end = i + ext_len as usize;
    if end > body.len() {
        return false;
    }

    while i + 4 <= end {
        let typ = u16::from_be_bytes(body[i..i + 2].try_into().unwrap());
        let len = u16::from_be_bytes(body[i + 2..i + 4].try_into().unwrap()) as usize;
        let data_at = i + 4;
        if data_at + len > end {
            return false;
        }

        if typ == EXT_KEY_SHARE && len >= 4 {
            let group = u16::from_be_bytes(body[data_at..data_at + 2].try_into().unwrap());
            let key_len =
                u16::from_be_bytes(body[data_at + 2..data_at + 4].try_into().unwrap()) as usize;
            let key_at = data_at + 4;
            if key_at + key_len > data_at + len {
                return false;
            }

            if group == GROUP_X25519 && key_len == 32 {
                body[key_at..key_at + 32].copy_from_slice(public);
                return true;
            }

            if group == GROUP_X25519_MLKEM768 && key_len >= 32 {
                let start = key_at + key_len - 32;
                body[start..start + 32].copy_from_slice(public);
                return true;
            }

            return false;
        }

        i = data_at + len;
    }

    false
}

pub fn build_server_hello_handshake(
    random: &[u8; 32],
    session_id: &[u8],
    cipher: u16,
    server_public: &[u8; 32],
    extension_order: &[u16],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0);

    let versions = ext(EXT_SUPPORTED_VERSIONS, &0x0304u16.to_be_bytes());
    let mut share = Vec::new();
    share.extend_from_slice(&GROUP_X25519.to_be_bytes());
    share.extend_from_slice(&32u16.to_be_bytes());
    share.extend_from_slice(server_public);
    let share = ext(EXT_KEY_SHARE, &share);

    let mut exts = Vec::new();
    for typ in extension_order {
        match *typ {
            EXT_SUPPORTED_VERSIONS => exts.extend_from_slice(&versions),
            EXT_KEY_SHARE => exts.extend_from_slice(&share),
            _ => {}
        }
    }
    if !extension_order.contains(&EXT_SUPPORTED_VERSIONS) {
        exts.extend_from_slice(&versions);
    }
    if !extension_order.contains(&EXT_KEY_SHARE) {
        exts.extend_from_slice(&share);
    }

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg = vec![2];
    msg.extend_from_slice(&u24_bytes(body.len()));
    msg.extend_from_slice(&body);
    msg
}

#[cfg(test)]
pub fn is_grease(value: u16) -> bool {
    GREASE.contains(&value)
}

#[cfg(test)]
fn signature_algorithms(handshake: &[u8]) -> Option<Vec<u16>> {
    let types_and_data = extension_types_and_data(handshake)?;
    let data = types_and_data
        .into_iter()
        .find(|(typ, _)| *typ == EXT_SIGNATURE_ALGORITHMS)?
        .1;
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes(data[0..2].try_into().ok()?) as usize;
    let list = data.get(2..2 + list_len)?;
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= list.len() {
        out.push(u16::from_be_bytes(list[i..i + 2].try_into().ok()?));
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
pub fn extension_types(handshake: &[u8]) -> Option<Vec<u16>> {
    Some(
        extension_types_and_data(handshake)?
            .into_iter()
            .map(|(typ, _)| typ)
            .collect(),
    )
}

#[cfg(test)]
fn extension_types_and_data(handshake: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    if handshake.len() < 42 || handshake[0] != 0x01 {
        return None;
    }

    let body_len = u24(&handshake[1..4])?;
    let body = handshake.get(4..4 + body_len)?;
    let mut i = 2 + 32;
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len;
    let cs_len = u16::from_be_bytes(body.get(i..i + 2)?.try_into().ok()?) as usize;
    i += 2 + cs_len;
    let comp_len = *body.get(i)? as usize;
    i += 1 + comp_len;
    let ext_len = u16::from_be_bytes(body.get(i..i + 2)?.try_into().ok()?) as usize;
    i += 2;
    let mut exts = body.get(i..i + ext_len)?;
    let mut out = Vec::new();

    while exts.len() >= 4 {
        let typ = u16::from_be_bytes(exts[0..2].try_into().ok()?);
        let len = u16::from_be_bytes(exts[2..4].try_into().ok()?) as usize;
        let data = exts.get(4..4 + len)?.to_vec();
        out.push((typ, data));
        exts = exts.get(4 + len..)?;
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_hello_session_id_stays_at_offset_39() {
        let random = [7u8; 32];
        let zeros = [0u8; 32];
        let public = [9u8; 32];
        let hello = build_client_hello_handshake(&random, &zeros, "www.microsoft.com", &public);
        assert_eq!(hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32], zeros);
        assert_eq!(hello[38], 32);
    }

    #[test]
    fn chrome_hello_parses_sni_and_x25519() {
        let random = [3u8; 32];
        let sid = [1u8; 32];
        let public = [0x11u8; 32];
        let hello = build_client_hello_handshake(&random, &sid, "www.microsoft.com", &public);
        let mut record = vec![0x16, 0x03, 0x01, 0, 0];
        let len = hello.len() as u16;
        record[3..5].copy_from_slice(&len.to_be_bytes());
        record.extend_from_slice(&hello);

        let view = ClientHelloView::parse(&record).expect("parse");
        assert_eq!(view.sni.as_deref(), Some("www.microsoft.com"));
        assert_eq!(view.x25519_public, Some(public));
        assert_eq!(view.session_id, sid);
        assert_eq!(view.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(view.alpn_class(), 2);
    }

    #[test]
    fn alpn_class_matches_xray_probe_buckets() {
        let view = |alpn: Vec<Vec<u8>>| ClientHelloView {
            random: [0u8; 32],
            session_id: Vec::new(),
            sni: None,
            x25519_public: None,
            alpn,
        };
        assert_eq!(view(vec![]).alpn_class(), 0);
        assert_eq!(view(vec![b"http/1.1".to_vec()]).alpn_class(), 1);
        assert_eq!(
            view(vec![b"h2".to_vec(), b"http/1.1".to_vec()]).alpn_class(),
            2
        );
        assert!(view(vec![b"acme-tls/1".to_vec()]).has_acme_alpn());
        assert!(!view(vec![b"h2".to_vec()]).has_acme_alpn());
    }

    #[test]
    fn chrome_hello_looks_like_chrome_131() {
        let hello =
            build_client_hello_handshake(&[0u8; 32], &[0u8; 32], "www.microsoft.com", &[2u8; 32]);
        let types = extension_types(&hello).expect("exts");
        assert!(is_grease(types[0]), "first extension is GREASE");
        assert!(
            is_grease(*types.last().unwrap()),
            "last extension is GREASE"
        );
        assert!(types.contains(&EXT_ECH));
        assert!(types.contains(&EXT_ALPN));
        assert!(types.contains(&EXT_KEY_SHARE));
        assert!(types.contains(&EXT_ALPS));
        assert!(types.contains(&EXT_COMPRESS_CERTIFICATE));
        assert_eq!(
            signature_algorithms(&hello).as_deref(),
            Some(
                [
                    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
                ]
                .as_slice()
            )
        );

        let body_len = u24(&hello[1..4]).unwrap();
        let body = &hello[4..4 + body_len];
        let cs_len = u16::from_be_bytes(body[67..69].try_into().unwrap()) as usize;
        let first_suite = u16::from_be_bytes(body[69..71].try_into().unwrap());
        assert!(is_grease(first_suite));
        assert_eq!(cs_len, 32);
    }

    fn mlkem768_from_hello(hello: &[u8]) -> Option<[u8; MLKEM768_PUBLIC_LEN]> {
        let types = parse_hello_key_shares(hello)?;
        types.into_iter().find_map(|(group, key)| {
            if group == GROUP_X25519_MLKEM768 && key.len() == MLKEM768_PUBLIC_LEN + 32 {
                key[..MLKEM768_PUBLIC_LEN].try_into().ok()
            } else {
                None
            }
        })
    }

    fn parse_hello_key_shares(hello: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
        let body_len = u24(&hello[1..4])?;
        let body = hello.get(4..4 + body_len)?;
        let mut i = 34usize;
        let sid_len = *body.get(i)? as usize;
        i += 1 + sid_len;
        let cs_len = u16::from_be_bytes(body.get(i..i + 2)?.try_into().ok()?) as usize;
        i += 2 + cs_len;
        let comp_len = *body.get(i)? as usize;
        i += 1 + comp_len;
        let ext_len = u16::from_be_bytes(body.get(i..i + 2)?.try_into().ok()?) as usize;
        i += 2;
        let mut exts = body.get(i..i + ext_len)?;

        while exts.len() >= 4 {
            let typ = u16::from_be_bytes(exts[0..2].try_into().ok()?);
            let len = u16::from_be_bytes(exts[2..4].try_into().ok()?) as usize;
            let data = exts.get(4..4 + len)?;
            exts = exts.get(4 + len..)?;
            if typ != EXT_KEY_SHARE {
                continue;
            }
            let list_len = u16::from_be_bytes(data.get(0..2)?.try_into().ok()?) as usize;
            let mut shares = data.get(2..2 + list_len)?;
            let mut out = Vec::new();
            while shares.len() >= 4 {
                let group = u16::from_be_bytes(shares[0..2].try_into().ok()?);
                let key_len = u16::from_be_bytes(shares[2..4].try_into().ok()?) as usize;
                let key = shares.get(4..4 + key_len)?.to_vec();
                shares = shares.get(4 + key_len..)?;
                out.push((group, key));
            }
            return Some(out);
        }

        None
    }

    #[test]
    fn chrome_hello_mlkem_public_is_valid() {
        let hello =
            build_client_hello_handshake(&[0u8; 32], &[0u8; 32], "www.microsoft.com", &[2u8; 32]);
        let pk_bytes = mlkem768_from_hello(&hello).expect("X25519MLKEM768 share");
        let pk = libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(pk_bytes);
        assert!(libcrux_ml_kem::mlkem768::validate_public_key(&pk));

        let again =
            build_client_hello_handshake(&[1u8; 32], &[0u8; 32], "www.microsoft.com", &[2u8; 32]);
        let other = mlkem768_from_hello(&again).expect("second share");
        assert_ne!(pk_bytes, other);
    }

    #[test]
    fn dest_server_hello_patch_keeps_ja3s() {
        let dest_pub = [0xAAu8; 32];
        let ours = [0xBBu8; 32];
        let mut hello = build_server_hello_handshake(
            &[1u8; 32],
            &[2u8; 32],
            0x1302,
            &dest_pub,
            &[EXT_KEY_SHARE, EXT_SUPPORTED_VERSIONS],
        );
        let before = ServerHelloView::parse(&hello).unwrap();
        assert_eq!(before.cipher, 0x1302);
        assert_eq!(
            before.extensions,
            vec![EXT_KEY_SHARE, EXT_SUPPORTED_VERSIONS]
        );
        assert_eq!(before.x25519_public, Some(dest_pub));

        assert!(patch_server_hello_x25519(&mut hello, &ours));
        let after = ServerHelloView::parse(&hello).unwrap();
        assert_eq!(before.ja3s(), after.ja3s());
        assert_eq!(after.x25519_public, Some(ours));
        assert_eq!(after.random, before.random);
    }
}
