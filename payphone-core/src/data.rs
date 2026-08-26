use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::FrameError;
use crate::all_good_dude::SESSION_ID_SIZE;

/// Размер фиксированной части DATA.
///
/// session_id = 16 bytes
/// packet_id  = 8 bytes
///
/// Итого:
///
/// 16 + 8 = 24 bytes
pub const DATA_HEADER_SIZE: usize = 24;

/// Максимальный payload одного DATA.
///
/// Пока ставим 64 KiB.
pub const MAX_DATA_PAYLOAD_SIZE: usize = 64 * 1024;

/// Пользовательские данные внутри PAYPHONE Session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Data {
    /// PAYPHONE Session ID.
    ///
    /// Сервер по нему понимает,
    /// к какой сессии относится пакет.
    pub session_id: [u8; SESSION_ID_SIZE],

    /// Номер DATA-пакета внутри Session.
    ///
    /// Например:
    ///
    /// 1
    /// 2
    /// 3
    pub packet_id: u64,

    /// Полезные данные.
    ///
    /// Сейчас здесь будет текст.
    ///
    /// Позже здесь будет настоящий IP packet
    /// из TUN.
    pub payload: Bytes,
}

impl Data {
    /// Создаёт новый DATA.
    pub fn new(session_id: [u8; SESSION_ID_SIZE], packet_id: u64, payload: Bytes) -> Self {
        Self {
            session_id,
            packet_id,
            payload,
        }
    }

    /// DATA -> bytes.
    pub fn encode(&self) -> Bytes {
        let payload_len = self.payload.len();

        let mut buffer = BytesMut::with_capacity(DATA_HEADER_SIZE + payload_len);

        // BYTE 0-15
        //
        // Session ID.
        buffer.extend_from_slice(&self.session_id);

        // BYTE 16-23
        //
        // Packet ID.
        buffer.put_u64(self.packet_id);

        // BYTE 24...
        //
        // Payload.
        buffer.extend_from_slice(&self.payload);

        buffer.freeze()
    }

    /// bytes -> DATA.
    pub fn decode(mut buffer: Bytes) -> Result<Self, FrameError> {
        // DATA обязан содержать
        // хотя бы:
        //
        // session_id + packet_id
        //
        // то есть 24 bytes.
        if buffer.len() < DATA_HEADER_SIZE {
            return Err(FrameError::InvalidDataLength);
        }

        // BYTE 0-15
        let mut session_id = [0u8; SESSION_ID_SIZE];

        buffer.copy_to_slice(&mut session_id);

        // BYTE 16-23
        let packet_id = buffer.get_u64();

        // Всё оставшееся —
        // DATA payload.
        let payload_len = buffer.remaining();

        if payload_len > MAX_DATA_PAYLOAD_SIZE {
            return Err(FrameError::DataPayloadTooLarge);
        }

        let payload = buffer.copy_to_bytes(payload_len);

        Ok(Self {
            session_id,
            packet_id,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_roundtrip() {
        let session_id = [7u8; 16];

        let original = Data::new(
            session_id,
            42,
            Bytes::from_static(b"Hello through PAYPHONE"),
        );

        let encoded = original.encode();

        let decoded = Data::decode(encoded).expect("DATA decode failed");

        assert_eq!(decoded.session_id, session_id);

        assert_eq!(decoded.packet_id, 42);

        assert_eq!(
            decoded.payload,
            Bytes::from_static(b"Hello through PAYPHONE")
        );
    }

    #[test]
    fn data_too_small_fails() {
        let data = Bytes::from_static(&[1, 2, 3]);

        let result = Data::decode(data);

        assert!(result.is_err());
    }
}
