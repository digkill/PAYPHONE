use std::{fs, path::Path};

use rand_core::{OsRng, TryRngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use super::auth::x25519_public;

#[derive(Clone, Copy, Debug)]
pub struct RealityKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

pub fn generate_keypair() -> RealityKeypair {
    let mut private = [0u8; 32];
    OsRng.try_fill_bytes(&mut private).expect("os rng");
    let secret = StaticSecret::from(private);
    let public = PublicKey::from(&secret).to_bytes();

    RealityKeypair { private, public }
}

pub fn parse_32_bytes(input: &str) -> Result<[u8; 32], String> {
    let input = input.trim();

    if input.is_empty() {
        return Err("empty REALITY key".into());
    }

    let path = Path::new(input);

    if path.is_file() {
        let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        return parse_32_bytes_raw(&bytes);
    }

    parse_32_bytes_raw(input.as_bytes())
}

fn parse_32_bytes_raw(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        return Ok(out);
    }

    let text = std::str::from_utf8(bytes)
        .map_err(|_| "REALITY key is not 32 raw bytes or UTF-8 text".to_string())?
        .trim();

    if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return hex_decode_32(text);
    }

    let decoded = b64_decode(text).ok_or_else(|| "REALITY key is not hex or base64".to_string())?;

    if decoded.len() != 32 {
        return Err(format!(
            "REALITY key decoded to {} bytes, expected 32",
            decoded.len()
        ));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

pub fn parse_short_id(input: &str) -> Result<[u8; 8], String> {
    let input = input.trim().trim_start_matches("0x");

    if input.is_empty() || input.len() > 16 || input.len() % 2 != 0 {
        return Err("REALITY shortId must be 1–8 hex bytes".into());
    }

    if !input.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("REALITY shortId must be hex".into());
    }

    let raw = hex_decode(input)?;
    let mut out = [0u8; 8];
    out[..raw.len()].copy_from_slice(&raw);
    Ok(out)
}

pub fn parse_short_ids(input: &str) -> Result<Vec<[u8; 8]>, String> {
    let mut ids = Vec::new();

    for part in input.split([',', ' ', ';']) {
        let part = part.trim();

        if part.is_empty() {
            continue;
        }

        ids.push(parse_short_id(part)?);
    }

    if ids.is_empty() {
        return Err("REALITY shortId list is empty".into());
    }

    Ok(ids)
}

#[allow(dead_code)]
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[allow(dead_code)]
pub fn encode_b64url(bytes: &[u8]) -> String {
    b64_encode(bytes, true)
}

#[allow(dead_code)]
pub fn public_from_private(private: &[u8; 32]) -> [u8; 32] {
    x25519_public(private)
}

fn hex_decode_32(text: &str) -> Result<[u8; 32], String> {
    let raw = hex_decode(text)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }

    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| "invalid hex".into()))
        .collect()
}

#[allow(dead_code)]
fn b64_encode(bytes: &[u8], url: bool) -> String {
    const STD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let table = if url { URL } else { STD };
    let mut out = String::new();
    let mut i = 0;

    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = bytes.get(i + 1).copied();
        let b2 = bytes.get(i + 2).copied();
        out.push(table[(b0 >> 2) as usize] as char);
        out.push(table[(((b0 & 0x03) << 4) | (b1.unwrap_or(0) >> 4)) as usize] as char);

        if b1.is_none() {
            break;
        }

        out.push(table[(((b1.unwrap() & 0x0f) << 2) | (b2.unwrap_or(0) >> 6)) as usize] as char);

        if b2.is_none() {
            break;
        }

        out.push(table[(b2.unwrap() & 0x3f) as usize] as char);
        i += 3;
    }

    out
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let text: String = text
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '=')
        .map(|ch| match ch {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();

    fn val(ch: u8) -> Option<u8> {
        match ch {
            b'A'..=b'Z' => Some(ch - b'A'),
            b'a'..=b'z' => Some(ch - b'a' + 26),
            b'0'..=b'9' => Some(ch - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let a = val(bytes[i])?;
        let b = val(*bytes.get(i + 1)?)?;
        out.push((a << 2) | (b >> 4));

        if let Some(c) = bytes.get(i + 2).copied().and_then(val) {
            out.push((b << 4) | (c >> 2));

            if let Some(d) = bytes.get(i + 3).copied().and_then(val) {
                out.push((c << 6) | d);
            }
        }

        i += 4;
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_b64_roundtrip() {
        let key = [0x11u8; 32];
        let hex = encode_hex(&key);
        assert_eq!(parse_32_bytes(&hex).unwrap(), key);

        let b64 = encode_b64url(&key);
        assert_eq!(parse_32_bytes(&b64).unwrap(), key);
    }

    #[test]
    fn short_id_pads() {
        assert_eq!(parse_short_id("aa").unwrap()[0], 0xaa);
        assert_eq!(
            &parse_short_id("aabbccdd").unwrap()[..4],
            &[0xaa, 0xbb, 0xcc, 0xdd]
        );
    }
}
