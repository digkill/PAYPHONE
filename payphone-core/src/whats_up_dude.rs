use bytes::{Buf, BufMut, Bytes, BytesMut};

use rand::RngCore;

use crate::{FrameError, PROTOCOL_VERSION};

/// Размер client nonce.
pub const CLIENT_NONCE_SIZE: usize = 32;

/// Фиксированная часть WhatsUpDude.
///
/// protocol_version = 1
/// client_version   = 2
/// capabilities     = 4
/// client_nonce     = 32
/// token_len        = 2
///
/// Итого:
///
/// 1 + 2 + 4 + 32 + 2 = 41 bytes
pub const WHATS_UP_DUDE_HEADER_SIZE: usize = 41;

/// Максимальный размер auth token.
///
/// Сейчас SubscriptionToken v1 = 135 bytes.
///
/// Но wire protocol сразу допускает
/// будущие версии token.
pub const MAX_AUTH_TOKEN_SIZE: usize = 2048;

// =============================================================
// CAPABILITIES
// =============================================================

pub const CAP_IPV4: u32 = 1 << 0;

pub const CAP_IPV6: u32 = 1 << 1;

pub const CAP_DNS: u32 = 1 << 2;

pub const CAP_RESUME: u32 = 1 << 3;

pub const CAP_ROAMING: u32 = 1 << 4;

// =============================================================
// WHATS UP DUDE
// =============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhatsUpDude {
    /// PAYPHONE/1.
    pub protocol_version: u8,

    /// Версия программы клиента.
    pub client_version: u16,

    /// Capabilities клиента.
    pub capabilities: u32,

    /// Случайные данные handshake.
    pub client_nonce: [u8; CLIENT_NONCE_SIZE],

    /// Подписочный PAYPHONE token.
    ///
    /// Здесь просто bytes.
    ///
    /// payphone-core ничего не знает
    /// про Ed25519 или подписки.
    ///
    /// Разбирать token будет
    /// payphone-auth на сервере.
    pub auth_token: Bytes,
}

impl WhatsUpDude {
    pub fn new(client_version: u16, capabilities: u32, auth_token: Bytes) -> Self {
        let mut client_nonce = [0u8; CLIENT_NONCE_SIZE];

        let mut rng = rand::rng();

        rng.fill_bytes(&mut client_nonce);

        Self {
            protocol_version: PROTOCOL_VERSION,

            client_version,

            capabilities,

            client_nonce,

            auth_token,
        }
    }

    pub fn supports(&self, capability: u32) -> bool {
        self.capabilities & capability != 0
    }

    // =========================================================
    // ENCODE
    // =========================================================

    pub fn encode(&self) -> Bytes {
        let token_len = self.auth_token.len();

        //
        // new() принимает Bytes любого размера,
        // поэтому encode защищаем assert.
        //
        // Позже можно перевести encode на Result,
        // но пока конструктор клиента будет
        // проверять token до создания Frame.
        //
        assert!(
            token_len <= MAX_AUTH_TOKEN_SIZE,
            "PAYPHONE auth token is too large"
        );

        assert!(
            token_len <= u16::MAX as usize,
            "PAYPHONE auth token cannot fit into u16"
        );

        let mut buffer = BytesMut::with_capacity(WHATS_UP_DUDE_HEADER_SIZE + token_len);

        // BYTE 0
        buffer.put_u8(self.protocol_version);

        // BYTE 1-2
        buffer.put_u16(self.client_version);

        // BYTE 3-6
        buffer.put_u32(self.capabilities);

        // BYTE 7-38
        buffer.extend_from_slice(&self.client_nonce);

        // BYTE 39-40
        buffer.put_u16(token_len as u16);

        // BYTE 41...
        buffer.extend_from_slice(&self.auth_token);

        buffer.freeze()
    }

    // =========================================================
    // DECODE
    // =========================================================

    pub fn decode(mut buffer: Bytes) -> Result<Self, FrameError> {
        //
        // Теперь WhatsUpDude
        // переменной длины.
        //
        // Поэтому проверяем не ==,
        // а минимальный header.
        //
        if buffer.len() < WHATS_UP_DUDE_HEADER_SIZE {
            return Err(FrameError::InvalidWhatsUpDudeLength);
        }

        let protocol_version = buffer.get_u8();

        let client_version = buffer.get_u16();

        let capabilities = buffer.get_u32();

        let mut client_nonce = [0u8; CLIENT_NONCE_SIZE];

        buffer.copy_to_slice(&mut client_nonce);

        //
        // Клиент сам сообщает,
        // сколько bytes занимает token.
        //
        let token_len = buffer.get_u16() as usize;

        if token_len == 0 {
            return Err(FrameError::MissingAuthToken);
        }

        if token_len > MAX_AUTH_TOKEN_SIZE {
            return Err(FrameError::AuthTokenTooLarge);
        }

        //
        // После token_len должно оставаться
        // ровно token_len bytes.
        //
        if buffer.remaining() != token_len {
            return Err(FrameError::InvalidAuthTokenLength);
        }

        let auth_token = buffer.copy_to_bytes(token_len);

        Ok(Self {
            protocol_version,
            client_version,
            capabilities,
            client_nonce,
            auth_token,
        })
    }
}

// =============================================================
// TESTS
// =============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whats_up_dude_roundtrip() {
        let token = Bytes::from_static(b"fake-subscription-token");

        let original = WhatsUpDude::new(1, CAP_IPV4 | CAP_IPV6 | CAP_DNS, token.clone());

        let encoded = original.encode();

        let decoded = WhatsUpDude::decode(encoded).expect("WhatsUpDude decode failed");

        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);

        assert_eq!(decoded.client_version, 1);

        assert!(decoded.supports(CAP_IPV4));

        assert!(decoded.supports(CAP_IPV6));

        assert!(decoded.supports(CAP_DNS));

        assert_eq!(decoded.auth_token, token);

        assert_eq!(decoded.client_nonce, original.client_nonce);
    }

    #[test]
    fn whats_up_dude_nonce_is_random() {
        let first = WhatsUpDude::new(1, 0, Bytes::from_static(b"token"));

        let second = WhatsUpDude::new(1, 0, Bytes::from_static(b"token"));

        assert_ne!(first.client_nonce, second.client_nonce);
    }

    #[test]
    fn invalid_size_fails() {
        let data = Bytes::from_static(&[1, 2, 3]);

        let result = WhatsUpDude::decode(data);

        assert!(result.is_err());
    }

    #[test]
    fn empty_token_fails() {
        let message = WhatsUpDude::new(1, 0, Bytes::new());

        let encoded = message.encode();

        let result = WhatsUpDude::decode(encoded);

        assert!(matches!(result, Err(FrameError::MissingAuthToken)));
    }
}
