use std::{cell::Cell, io};

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

//
// 2-byte big-endian длина реального payload, дописывается перед
// самим payload (внутри того, что потом XOR'ится) — нужна, чтобы
// deobfuscate() знал, где заканчиваются настоящие данные и
// начинается padding.
//
const LENGTH_PREFIX_LEN: usize = 2;

//
// Без padding итоговая длина на проводе однозначно повторяет
// длину реальной QUIC-датаграммы (плюс фиксированные +8 salt) —
// последовательность размеров почти не отличается от учебного
// QUIC/HTTP3. Добавляем небольшой случайный "хвост", чтобы
// сломать эту точную сигнатуру.
//
// ВАЖНО: это НЕБОЛЬШОЙ и РАВНОМЕРНЫЙ паддинг, не округление до
// далёких друг от друга "бакетов". Первая версия округляла размер
// вверх до одного из [128, 296, 568, 1200, 1440] — для пакета
// ровно на 1200-байтной MTU-границе это означало скачок сразу до
// 1440 (+230 байт). Каждый пакет, включая служебные PMTU-discovery
// пробы самого quinn, проходит именно через этот слой обфускации
// (см. `ObfuscatedSocket`), поэтому такой скачок мог раздувать
// пробный пакет quinn выше реального MTU пути, проба терялась, и
// quinn занижал свою оценку допустимого размера датаграммы — вплоть
// до `SendDatagramError::TooLarge` на честных MTU-размера кадрах
// (воспроизведено на реальном деплое после включения бакетов).
// Маленький ограниченный паддинг такого искажения не создаёт.
//
const MAX_PADDING: usize = 32;

fn fill_random(out: &mut [u8]) {
    //
    // OsRng on every datagram was a syscall on the hot path
    // (salt + padding for every QUIC packet, including ACKs).
    // One OS seed per thread, then xorshift, is enough for
    // obfuscation salt — this layer is not encryption.
    //
    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0) };
    }

    STATE.with(|cell| {
        let mut state = cell.get();

        if state == 0 {
            let mut seed = [0u8; 8];

            let _ = OsRng.try_fill_bytes(&mut seed);

            state = u64::from_le_bytes(seed) | 1;
        }

        let mut offset = 0;

        while offset < out.len() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;

            let bytes = state.to_le_bytes();

            let take = (out.len() - offset).min(8);

            out[offset..offset + take].copy_from_slice(&bytes[..take]);

            offset += take;
        }

        cell.set(state);
    });
}

fn random_pad_len() -> usize {
    let mut byte = [0u8; 1];

    fill_random(&mut byte);

    byte[0] as usize % (MAX_PADDING + 1)
}

//
// Буквальный placeholder из .env.example. Ничего не мешает
// случайно задеплоить сервер/клиент с этим значением как есть —
// тогда обфускация даёт нулевую защиту любому, кто прочитал
// публичный репозиторий и знает этот пароль.
//
const PLACEHOLDER_PASSPHRASE: &str = "change-me-to-a-real-random-secret";

//
// Не крипто-строгая проверка — просто анти-footgun на старте
// процесса: явный отказ вместо тихого запуска с известным всем
// секретом или совсем коротким/легко перебираемым паролем.
//
pub fn validate_passphrase(passphrase: &str) -> Result<(), &'static str> {
    if passphrase == PLACEHOLDER_PASSPHRASE {
        return Err(
            "PAYPHONE_OBFS_PSK is still the placeholder from .env.example; \
             generate a real secret, e.g. `openssl rand -hex 32`",
        );
    }

    if passphrase.len() < 16 {
        return Err("PAYPHONE_OBFS_PSK is too short; use at least 16 characters of real entropy");
    }

    Ok(())
}

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
    // salt (случайный) + XOR(
    //   [2-byte длина payload][payload][небольшой случайный padding],
    //   keystream, зациклённый
    // )
    //
    // pad_len — равномерно случайный [0, MAX_PADDING] на каждый
    // вызов, независимо от размера payload (см. комментарий у
    // MAX_PADDING про то, почему не бакеты).
    //
    pub fn obfuscate(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.obfuscate_padded(payload, random_pad_len())
    }

    /// Same as [`Self::obfuscate`], but the padding length is chosen by the
    /// caller. GSO needs every segment in a batch to grow by the same amount
    /// so UDP_SEGMENT still sees equal-sized chunks.
    pub fn obfuscate_padded(&self, payload: &[u8], pad_len: usize) -> io::Result<Vec<u8>> {
        let pad_len = pad_len.min(MAX_PADDING);

        let mut salt = [0u8; SALT_LEN];

        fill_random(&mut salt);

        let stream = self.keystream(&salt);

        let payload_len: u16 = payload
            .len()
            .try_into()
            .map_err(|_| io::Error::other("payload too large to obfuscate (> 65535 bytes)"))?;

        let mut padding = vec![0u8; pad_len];

        fill_random(&mut padding);

        //
        // Всё, что XOR'ится: [длина][payload][padding].
        //
        let mut plaintext = Vec::with_capacity(LENGTH_PREFIX_LEN + payload.len() + pad_len);

        plaintext.extend_from_slice(&payload_len.to_be_bytes());

        plaintext.extend_from_slice(payload);

        plaintext.extend_from_slice(&padding);

        let mut out = Vec::with_capacity(SALT_LEN + plaintext.len());

        out.extend_from_slice(&salt);

        out.extend(
            plaintext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ stream[index % KEY_LEN]),
        );

        Ok(out)
    }

    pub(crate) fn gso_pad_len() -> usize {
        random_pad_len()
    }

    //
    // Обратная операция.
    //
    // `None`, если `data` короче salt+length-prefix или заявленная
    // в префиксе длина не сходится с тем, что реально есть в
    // датаграмме — считаем это шумом/probe'ом, а не PAYPHONE-
    // трафиком, и никогда не передаём quinn.
    //
    pub fn deobfuscate(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < SALT_LEN + LENGTH_PREFIX_LEN {
            return None;
        }

        let mut salt = [0u8; SALT_LEN];

        salt.copy_from_slice(&data[..SALT_LEN]);

        let stream = self.keystream(&salt);

        let plaintext: Vec<u8> = data[SALT_LEN..]
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ stream[index % KEY_LEN])
            .collect();

        let payload_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;

        plaintext
            .get(LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + payload_len)
            .map(|payload| payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_passphrase_is_rejected() {
        assert!(validate_passphrase(PLACEHOLDER_PASSPHRASE).is_err());
    }

    #[test]
    fn short_passphrase_is_rejected() {
        assert!(validate_passphrase("too-short").is_err());
    }

    #[test]
    fn real_passphrase_is_accepted() {
        assert!(validate_passphrase("a-real-32-byte-hex-secret-value").is_ok());
    }

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

        //
        // С неверным ключом deobfuscate либо вернёт мусор (не
        // совпадающий с исходным payload), либо None — если
        // "длина" из чужого keystream окажется больше остатка
        // данных. Оба исхода корректны, важно только что payload
        // никогда не воспроизводится по ошибке.
        //
        match other.deobfuscate(&wire) {
            Some(plain) => assert_ne!(plain, payload),

            None => {}
        }
    }

    #[test]
    fn too_short_is_rejected() {
        let key = ObfuscationKey::from_passphrase("test-passphrase");

        assert!(key.deobfuscate(&[1, 2, 3]).is_none());
    }

    #[test]
    fn padding_stays_within_bound() {
        let key = ObfuscationKey::from_passphrase("test-passphrase");

        //
        // Паддинг маленький и равномерный — никаких далёких
        // "прыжков" по размеру (см. комментарий у MAX_PADDING про
        // то, почему бакеты сломали PMTU discovery в quinn).
        //
        for len in [0usize, 1, 40, 120, 300, 600, 1199, 1300, 1465] {
            let payload = vec![0xABu8; len];

            let wire = key.obfuscate(&payload).expect("obfuscate failed");

            let min_len = SALT_LEN + LENGTH_PREFIX_LEN + len;

            let max_len = min_len + MAX_PADDING;

            assert!(
                (min_len..=max_len).contains(&wire.len()),
                "wire length {} for payload length {} outside expected [{}, {}]",
                wire.len(),
                len,
                min_len,
                max_len,
            );

            let plain = key.deobfuscate(&wire).expect("deobfuscate failed");

            assert_eq!(plain, payload);
        }
    }

    #[test]
    fn fixed_pad_keeps_gso_segments_equal() {
        let key = ObfuscationKey::from_passphrase("test-passphrase");

        let a = vec![0x11u8; 400];

        let b = vec![0x22u8; 400];

        let first = key.obfuscate_padded(&a, 7).expect("obfuscate");

        let second = key.obfuscate_padded(&b, 7).expect("obfuscate");

        assert_eq!(first.len(), second.len());

        assert_eq!(key.deobfuscate(&first).expect("plain a"), a.as_slice());

        assert_eq!(key.deobfuscate(&second).expect("plain b"), b.as_slice());
    }

    #[test]
    fn large_payload_roundtrips() {
        let key = ObfuscationKey::from_passphrase("test-passphrase");

        let payload = vec![0x42u8; 2000];

        let wire = key.obfuscate(&payload).expect("obfuscate failed");

        let plain = key.deobfuscate(&wire).expect("deobfuscate failed");

        assert_eq!(plain, payload);
    }
}
