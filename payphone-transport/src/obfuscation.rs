use std::io;

use rand_core::{OsRng, TryRngCore};

use sha2::{Digest, Sha256};

//
// Обфускация UDP-пакетов (в стиле "Salamander" из Hysteria2).
//
// ЗАЧЕМ:
//
// QUIC имеет узнаваемую сигнатуру на проводе (long header,
// version negotiation) независимо от порта. DPI на основе ТСПУ
// не только матчит эту сигнатуру пассивно, но и делает активный
// probing: увидев подозрительный UDP-поток на IP:port, сам
// подключается туда и пытается завершить QUIC handshake, чтобы
// подтвердить VPN-сервер и заблокировать его.
//
// ЧТО ЭТО НЕ ДАЁТ:
//
// Это не шифрование в криптографическом смысле — конфиденциальность
// и целостность уже обеспечивает TLS 1.3 внутри самого QUIC. Единственная
// задача этого слоя — сделать так, чтобы PAYPHONE-датаграммы перестали
// выглядеть как QUIC на проводе, и чтобы у стороны без общего passphrase
// не было способа собрать байты, которые quinn примет за начало
// handshake — то есть слепой probe просто не получит ответа.
//
// КАК:
//
// [salt: 8 bytes][XOR(payload, tiled SHA256(key || salt))]
//
// salt случайный на каждый исходящий пакет, поэтому одинаковый
// payload каждый раз даёт разные байты на проводе.
//

pub const SALT_LEN: usize = 8;

const KEY_LEN: usize = 32;

#[derive(Clone)]
pub struct ObfuscationKey([u8; KEY_LEN]);

impl ObfuscationKey {
    //
    // Пароль -> фиксированный 32-byte key через SHA256.
    //
    // Пароль должен быть одинаковым
    // на клиенте и на сервере.
    //
    pub fn from_passphrase(passphrase: &str) -> Self {
        let digest = Sha256::digest(passphrase.as_bytes());

        let mut key = [0u8; KEY_LEN];

        key.copy_from_slice(&digest);

        Self(key)
    }

    fn keystream(&self, salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
        let mut hasher = Sha256::new();

        hasher.update(self.0);

        hasher.update(salt);

        let digest = hasher.finalize();

        let mut stream = [0u8; KEY_LEN];

        stream.copy_from_slice(&digest);

        stream
    }

    //
    // salt (случайный) + XOR(payload, keystream, зациклённый).
    //
    pub fn obfuscate(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut salt = [0u8; SALT_LEN];

        OsRng.try_fill_bytes(&mut salt).map_err(io::Error::other)?;

        let stream = self.keystream(&salt);

        let mut out = Vec::with_capacity(SALT_LEN + payload.len());

        out.extend_from_slice(&salt);

        out.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ stream[index % KEY_LEN]),
        );

        Ok(out)
    }

    //
    // Обратная операция.
    //
    // `None`, если `data` короче salt — считаем это шумом/probe'ом,
    // а не PAYPHONE-трафиком, и никогда не передаём quinn.
    //
    pub fn deobfuscate(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < SALT_LEN {
            return None;
        }

        let mut salt = [0u8; SALT_LEN];

        salt.copy_from_slice(&data[..SALT_LEN]);

        let stream = self.keystream(&salt);

        Some(
            data[SALT_LEN..]
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ stream[index % KEY_LEN])
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = ObfuscationKey::from_passphrase("test-passphrase");

        let payload = b"hello quic handshake bytes, more than 32 bytes of them to check tiling";

        let wire = key.obfuscate(payload).expect("obfuscate failed");

        let plain = key.deobfuscate(&wire).expect("deobfuscate failed");

        assert_eq!(plain, payload);
    }

    #[test]
    fn different_salt_each_time() {
        let key = ObfuscationKey::from_passphrase("test-passphrase");

        let payload = b"same payload";

        let first = key.obfuscate(payload).expect("obfuscate failed");

        let second = key.obfuscate(payload).expect("obfuscate failed");

        assert_ne!(first, second);
    }

    #[test]
    fn wrong_key_does_not_roundtrip() {
        let key = ObfuscationKey::from_passphrase("correct-passphrase");

        let other = ObfuscationKey::from_passphrase("wrong-passphrase");

        let payload = b"secret bytes";

        let wire = key.obfuscate(payload).expect("obfuscate failed");

        let plain = other.deobfuscate(&wire).expect("deobfuscate failed");

        assert_ne!(plain, payload);
    }

    #[test]
    fn too_short_is_rejected() {
        let key = ObfuscationKey::from_passphrase("test-passphrase");

        assert!(key.deobfuscate(&[1, 2, 3]).is_none());
    }
}
