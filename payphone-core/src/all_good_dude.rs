use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::RngCore;

use crate::{FrameError, PROTOCOL_VERSION};

pub const SESSION_ID_SIZE: usize = 16;
pub const SERVER_NONCE_SIZE: usize = 32;

pub const ALL_GOOD_DUDE_SIZE: usize = 59;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllGoodDude {
    /// Версия протокола PAYPHONE.
    pub protocol_version: u8,

    /// Уникальный ID PAYPHONE-сессии.
    pub session_id: [u8; SESSION_ID_SIZE],

    /// Внутренний IPv4-адрес клиента.
    ///
    /// Например:
    ///
    /// 10.77.0.2
    pub assigned_ipv4: [u8; 4],

    /// MTU PAYPHONE-туннеля.
    pub mtu: u16,

    /// Возможности, которые согласованы
    /// между клиентом и сервером.
    pub capabilities: u32,

    /// Случайные 32 байта сервера.
    pub server_nonce: [u8; SERVER_NONCE_SIZE],
}

impl AllGoodDude {
    pub fn new(assigned_ipv4: [u8; 4], mtu: u16, capabilities: u32) -> Self {
        // Создаём пустой Session ID.
        let mut session_id = [0u8; SESSION_ID_SIZE];

        // Создаём пустой server nonce.
        let mut server_nonce = [0u8; SERVER_NONCE_SIZE];

        // Получаем генератор случайных чисел.
        let mut rng = rand::rng();

        // Заполняем Session ID
        // случайными байтами.
        rng.fill_bytes(&mut session_id);

        // Заполняем server nonce
        // случайными байтами.
        rng.fill_bytes(&mut server_nonce);

        Self {
            protocol_version: PROTOCOL_VERSION,

            session_id,

            assigned_ipv4,

            mtu,

            capabilities,

            server_nonce,
        }
    }

    /// AllGoodDude -> bytes
    pub fn encode(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(ALL_GOOD_DUDE_SIZE);

        // BYTE 0
        //
        // protocol_version
        buffer.put_u8(self.protocol_version);

        // BYTE 1-16
        //
        // session_id
        buffer.extend_from_slice(&self.session_id);

        // BYTE 17-20
        //
        // assigned IPv4
        buffer.extend_from_slice(&self.assigned_ipv4);

        // BYTE 21-22
        //
        // MTU
        buffer.put_u16(self.mtu);

        // BYTE 23-26
        //
        // capabilities
        buffer.put_u32(self.capabilities);

        // BYTE 27-58
        //
        // server_nonce
        buffer.extend_from_slice(&self.server_nonce);

        buffer.freeze()
    }

    /// bytes -> AllGoodDude
    pub fn decode(mut buffer: Bytes) -> Result<Self, FrameError> {
        if buffer.len() != ALL_GOOD_DUDE_SIZE {
            return Err(FrameError::InvalidAllGoodDudeLength);
        }

        // BYTE 0
        let protocol_version = buffer.get_u8();

        // BYTE 1-16
        let mut session_id = [0u8; SESSION_ID_SIZE];

        buffer.copy_to_slice(&mut session_id);

        // BYTE 17-20
        let mut assigned_ipv4 = [0u8; 4];

        buffer.copy_to_slice(&mut assigned_ipv4);

        // BYTE 21-22
        let mtu = buffer.get_u16();

        // BYTE 23-26
        let capabilities = buffer.get_u32();

        // BYTE 27-58
        let mut server_nonce = [0u8; SERVER_NONCE_SIZE];

        buffer.copy_to_slice(&mut server_nonce);

        Ok(Self {
            protocol_version,
            session_id,
            assigned_ipv4,
            mtu,
            capabilities,
            server_nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_good_dude_roundtrip() {
        let original = AllGoodDude::new([10, 77, 0, 2], 1280, 7);

        let encoded = original.encode();

        assert_eq!(encoded.len(), ALL_GOOD_DUDE_SIZE);

        let decoded = AllGoodDude::decode(encoded).expect("AllGoodDude decode failed");

        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);

        assert_eq!(decoded.assigned_ipv4, [10, 77, 0, 2]);

        assert_eq!(decoded.mtu, 1280);

        assert_eq!(decoded.capabilities, 7);

        assert_eq!(decoded.session_id, original.session_id);

        assert_eq!(decoded.server_nonce, original.server_nonce);
    }

    #[test]
    fn session_id_is_random() {
        let first = AllGoodDude::new([10, 77, 0, 2], 1280, 0);

        let second = AllGoodDude::new([10, 77, 0, 2], 1280, 0);

        assert_ne!(first.session_id, second.session_id);
    }
}
