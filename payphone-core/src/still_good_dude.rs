use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{FrameError, all_good_dude::SESSION_ID_SIZE};

/// Размер StillGoodDude.
///
/// session_id   = 16 bytes
/// assigned_ip  = 4 bytes
/// mtu          = 2 bytes
/// capabilities = 4 bytes
///
/// Итого:
///
/// 16 + 4 + 2 + 4 = 26 bytes
pub const STILL_GOOD_DUDE_SIZE: usize = SESSION_ID_SIZE + 4 + 2 + 4;

/// Ответ сервера на успешный Session Resume.
///
/// Клиент:
///
/// BackAgainDude
///
/// Сервер:
///
/// StillGoodDude
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StillGoodDude {
    /// Восстановленный Session ID.
    pub session_id: [u8; SESSION_ID_SIZE],

    /// Внутренний PAYPHONE IPv4.
    ///
    /// Например:
    ///
    /// 10.77.0.2
    ///
    /// При Resume он остаётся тем же.
    pub assigned_ipv4: [u8; 4],

    /// MTU PAYPHONE tunnel.
    pub mtu: u16,

    /// Capabilities этой Session.
    pub capabilities: u32,
}

impl StillGoodDude {
    /// Создаёт StillGoodDude.
    pub fn new(
        session_id: [u8; SESSION_ID_SIZE],

        assigned_ipv4: [u8; 4],

        mtu: u16,

        capabilities: u32,
    ) -> Self {
        Self {
            session_id,
            assigned_ipv4,
            mtu,
            capabilities,
        }
    }

    /// StillGoodDude -> bytes.
    pub fn encode(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(STILL_GOOD_DUDE_SIZE);

        //
        // BYTE 0-15
        //
        // Session ID.
        //
        buffer.extend_from_slice(&self.session_id);

        //
        // BYTE 16-19
        //
        // IPv4.
        //
        // Например:
        //
        // 10 77 0 2
        //
        buffer.extend_from_slice(&self.assigned_ipv4);

        //
        // BYTE 20-21
        //
        // MTU.
        //
        buffer.put_u16(self.mtu);

        //
        // BYTE 22-25
        //
        // Capabilities.
        //
        buffer.put_u32(self.capabilities);

        buffer.freeze()
    }

    /// bytes -> StillGoodDude.
    pub fn decode(mut buffer: Bytes) -> Result<Self, FrameError> {
        //
        // Сообщение обязано быть
        // ровно 26 bytes.
        //
        if buffer.len() != STILL_GOOD_DUDE_SIZE {
            return Err(FrameError::InvalidStillGoodDudeLength);
        }

        //
        // BYTE 0-15
        //
        let mut session_id = [0u8; SESSION_ID_SIZE];

        buffer.copy_to_slice(&mut session_id);

        //
        // BYTE 16-19
        //
        let mut assigned_ipv4 = [0u8; 4];

        buffer.copy_to_slice(&mut assigned_ipv4);

        //
        // BYTE 20-21
        //
        let mtu = buffer.get_u16();

        //
        // BYTE 22-25
        //
        let capabilities = buffer.get_u32();

        Ok(Self {
            session_id,
            assigned_ipv4,
            mtu,
            capabilities,
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
    fn still_good_dude_roundtrip() {
        let session_id = [5u8; SESSION_ID_SIZE];

        let original = StillGoodDude::new(session_id, [10, 77, 0, 2], 1280, 13);

        //
        // Struct -> bytes.
        //
        let encoded = original.encode();

        //
        // Размер должен быть 26 bytes.
        //
        assert_eq!(encoded.len(), STILL_GOOD_DUDE_SIZE);

        //
        // bytes -> struct.
        //
        let decoded = StillGoodDude::decode(encoded).expect("StillGoodDude decode failed");

        assert_eq!(decoded.session_id, session_id);

        assert_eq!(decoded.assigned_ipv4, [10, 77, 0, 2,]);

        assert_eq!(decoded.mtu, 1280);

        assert_eq!(decoded.capabilities, 13);
    }

    #[test]
    fn invalid_still_good_dude_size_fails() {
        let data = Bytes::from_static(&[1, 2, 3]);

        let result = StillGoodDude::decode(data);

        assert!(result.is_err());
    }
}
