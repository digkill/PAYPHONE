use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{FrameError, all_good_dude::SESSION_ID_SIZE};

/// Размер PAYPHONE PONG.
///
/// session_id = 16 bytes
/// ping_id    = 8 bytes
///
/// Итого:
///
/// 24 bytes.
pub const PONG_SIZE: usize = 24;

/// Ответ сервера на PING.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pong {
    /// Session ID.
    pub session_id: [u8; SESSION_ID_SIZE],

    /// ID того PING,
    /// на который сервер отвечает.
    pub ping_id: u64,
}

impl Pong {
    pub fn new(session_id: [u8; SESSION_ID_SIZE], ping_id: u64) -> Self {
        Self {
            session_id,
            ping_id,
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(PONG_SIZE);

        buffer.extend_from_slice(&self.session_id);

        buffer.put_u64(self.ping_id);

        buffer.freeze()
    }

    pub fn decode(mut buffer: Bytes) -> Result<Self, FrameError> {
        if buffer.len() != PONG_SIZE {
            return Err(FrameError::InvalidPongLength);
        }

        let mut session_id = [0u8; SESSION_ID_SIZE];

        buffer.copy_to_slice(&mut session_id);

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
    fn pong_roundtrip() {
        let original = Pong::new([9u8; 16], 123);

        let encoded = original.encode();

        assert_eq!(encoded.len(), PONG_SIZE);

        let decoded = Pong::decode(encoded).expect("PONG decode failed");

        assert_eq!(decoded.session_id, [9u8; 16]);

        assert_eq!(decoded.ping_id, 123);
    }
}
