use bytes::{Buf, Bytes, BytesMut};

use crate::{
    FrameError,
    all_good_dude::{SERVER_NONCE_SIZE, SESSION_ID_SIZE},
};

/// Размер BackAgainDude.
///
/// session_id   = 16 bytes
/// resume_token = 32 bytes
///
/// Итого:
///
/// 48 bytes
pub const BACK_AGAIN_DUDE_SIZE: usize = SESSION_ID_SIZE + SERVER_NONCE_SIZE;

/// Сообщение клиента
/// для восстановления старой PAYPHONE Session.
///
/// Клиент говорит серверу:
///
/// "Back again, dude?"
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackAgainDude {
    /// ID Session,
    /// которую клиент хочет восстановить.
    pub session_id: [u8; SESSION_ID_SIZE],

    /// Секретный token,
    /// который клиент получил
    /// при первоначальном создании Session.
    ///
    /// Пока мы используем server_nonce.
    pub resume_token: [u8; SERVER_NONCE_SIZE],
}

impl BackAgainDude {
    /// Создаёт новый BackAgainDude.
    pub fn new(session_id: [u8; SESSION_ID_SIZE], resume_token: [u8; SERVER_NONCE_SIZE]) -> Self {
        Self {
            session_id,
            resume_token,
        }
    }

    /// BackAgainDude -> bytes.
    ///
    /// Формат:
    ///
    /// BYTE 0-15
    /// session_id
    ///
    /// BYTE 16-47
    /// resume_token
    pub fn encode(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(BACK_AGAIN_DUDE_SIZE);

        //
        // BYTE 0-15
        //
        // Session ID.
        //
        buffer.extend_from_slice(&self.session_id);

        //
        // BYTE 16-47
        //
        // Resume Token.
        //
        buffer.extend_from_slice(&self.resume_token);

        buffer.freeze()
    }

    /// bytes -> BackAgainDude.
    pub fn decode(mut buffer: Bytes) -> Result<Self, FrameError> {
        //
        // Размер обязан быть
        // строго 48 bytes.
        //
        if buffer.len() != BACK_AGAIN_DUDE_SIZE {
            return Err(FrameError::InvalidBackAgainDudeLength);
        }

        //
        // Создаём пустой массив
        // для Session ID.
        //
        let mut session_id = [0u8; SESSION_ID_SIZE];

        //
        // Читаем первые 16 bytes.
        //
        buffer.copy_to_slice(&mut session_id);

        //
        // Создаём массив
        // для Resume Token.
        //
        let mut resume_token = [0u8; SERVER_NONCE_SIZE];

        //
        // Читаем оставшиеся 32 bytes.
        //
        buffer.copy_to_slice(&mut resume_token);

        Ok(Self {
            session_id,
            resume_token,
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
    fn back_again_dude_roundtrip() {
        let session_id = [7u8; SESSION_ID_SIZE];

        let resume_token = [9u8; SERVER_NONCE_SIZE];

        let original = BackAgainDude::new(session_id, resume_token);

        //
        // Struct -> bytes.
        //
        let encoded = original.encode();

        //
        // Проверяем размер.
        //
        assert_eq!(encoded.len(), BACK_AGAIN_DUDE_SIZE);

        //
        // bytes -> struct.
        //
        let decoded = BackAgainDude::decode(encoded).expect("BackAgainDude decode failed");

        assert_eq!(decoded.session_id, session_id);

        assert_eq!(decoded.resume_token, resume_token);
    }

    #[test]
    fn invalid_back_again_dude_size_fails() {
        //
        // Здесь только 3 bytes.
        //
        // Нужно 48.
        //
        let data = Bytes::from_static(&[1, 2, 3]);

        let result = BackAgainDude::decode(data);

        assert!(result.is_err());
    }
}
