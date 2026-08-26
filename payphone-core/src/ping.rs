use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{FrameError, all_good_dude::SESSION_ID_SIZE};

/// Размер PAYPHONE PING.
///
/// session_id = 16 bytes
/// ping_id    = 8 bytes
///
/// Итого:
///
/// 16 + 8 = 24 bytes
pub const PING_SIZE: usize = 24;

/// PAYPHONE PING.
///
/// Клиент периодически отправляет его серверу,
/// чтобы сервер понимал:
///
/// "эта Session ещё жива".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    /// Session, к которой относится PING.
    pub session_id: [u8; SESSION_ID_SIZE],

    /// Номер конкретного PING.
    ///
    /// Например:
    ///
    /// 1
    /// 2
    /// 3
    pub ping_id: u64,
}

impl Ping {
    /// Создаём новый PING.
    pub fn new(session_id: [u8; SESSION_ID_SIZE], ping_id: u64) -> Self {
        Self {
            session_id,
            ping_id,
        }
    }

    /// Ping -> bytes.
    pub fn encode(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(PING_SIZE);

        // BYTE 0-15
        //
        // Session ID.
        buffer.extend_from_slice(&self.session_id);

        // BYTE 16-23
        //
        // Ping ID.
        buffer.put_u64(self.ping_id);

        buffer.freeze()
    }

    /// bytes -> Ping.
    pub fn decode(mut buffer: Bytes) -> Result<Self, FrameError> {
        // PING всегда имеет ровно 24 bytes.
        if buffer.len() != PING_SIZE {
            return Err(FrameError::InvalidPingLength);
        }

        // Читаем Session ID.
        let mut session_id = [0u8; SESSION_ID_SIZE];

        buffer.copy_to_slice(&mut session_id);

        // Читаем ping_id.
        let ping_id = buffer.get_u64();

        Ok(Self {
            session_id,
            ping_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_roundtrip() {
        let original = Ping::new([7u8; 16], 42);

        let encoded = original.encode();

        assert_eq!(encoded.len(), PING_SIZE);

        let decoded = Ping::decode(encoded).expect("PING decode failed");

        assert_eq!(decoded.session_id, [7u8; 16]);

        assert_eq!(decoded.ping_id, 42);
    }
}
