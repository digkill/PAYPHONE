use bytes::{Buf, BufMut, Bytes, BytesMut};

//
// Подключаем модули PAYPHONE core.
//
pub mod access_denied_dude;
pub mod all_good_dude;
pub mod back_again_dude;
pub mod data;
pub mod ping;
pub mod pong;
pub mod still_good_dude;
pub mod whats_up_dude;

//
// =============================================================
// GLOBAL PROTOCOL CONSTANTS
// =============================================================
//

/// Версия wire protocol.
///
/// Сейчас:
///
/// PAYPHONE/1
pub const PROTOCOL_VERSION: u8 = 1;

/// Стандартный порт PAYPHONE server.
pub const DEFAULT_PORT: u16 = 40404;

/// Размер фиксированного заголовка PAYPHONE Frame.
///
/// version      = 1 byte
/// frame_type   = 1 byte
/// flags        = 2 bytes
/// payload_len  = 4 bytes
/// sequence     = 8 bytes
///
/// Итого:
///
/// 1 + 1 + 2 + 4 + 8 = 16 bytes.
pub const HEADER_SIZE: usize = 16;

/// Максимальный размер Frame payload.
///
/// 64 KiB.
pub const MAX_PAYLOAD_SIZE: usize = 64 * 1024;

//
// =============================================================
// FRAME TYPE
// =============================================================
//

/// Тип PAYPHONE Frame.
///
/// #[repr(u8)]
///
/// означает:
///
/// каждый вариант enum
/// реально имеет конкретное
/// числовое значение размером 1 byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Пользовательские данные.
    ///
    /// Позже внутри DATA
    /// будут реальные IP packets
    /// из TUN.
    Data = 1,

    /// Первое сообщение нового клиента.
    ///
    /// "What's up, dude?"
    WhatsUpDude = 2,

    /// Ответ сервера
    /// на новый handshake.
    ///
    /// "All good, dude."
    AllGoodDude = 3,

    /// Keepalive request.
    Ping = 4,

    /// Keepalive response.
    Pong = 5,

    /// Обновление
    /// криптографического состояния.
    Rekey = 6,

    /// Завершение PAYPHONE Session.
    Close = 7,

    /// Запрос клиента
    /// на восстановление старой Session.
    ///
    /// "Back again, dude?"
    BackAgainDude = 8,

    /// Сервер подтверждает,
    /// что Session успешно восстановлена.
    ///
    /// "Still good, dude."
    StillGoodDude = 9,

    /// Сервер отказал клиенту.
    ///
    /// "Access denied, dude."
    AccessDeniedDude = 10,
}

//
// =============================================================
// FRAME ERRORS
// =============================================================
//

/// Ошибки wire protocol PAYPHONE.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Получено меньше HEADER_SIZE bytes.
    #[error("frame is too small")]
    TooSmall,

    /// Неизвестный FrameType.
    #[error("unknown frame type: {0}")]
    UnknownFrameType(u8),

    /// Payload превышает
    /// максимально разрешённый размер.
    #[error("payload is too large")]
    PayloadTooLarge,

    /// payload_len в header
    /// не совпадает с количеством
    /// реально оставшихся bytes.
    #[error("invalid payload length")]
    InvalidPayloadLength,

    /// Неизвестная версия PAYPHONE.
    #[error("unsupported PAYPHONE version: {0}")]
    UnsupportedVersion(u8),

    /// Неправильный размер WhatsUpDude.
    #[error("invalid WhatsUpDude length")]
    InvalidWhatsUpDudeLength,

    /// Неправильный размер AllGoodDude.
    #[error("invalid AllGoodDude length")]
    InvalidAllGoodDudeLength,

    /// Неправильный размер BackAgainDude.
    #[error("invalid BackAgainDude length")]
    InvalidBackAgainDudeLength,

    /// Неправильный размер StillGoodDude.
    #[error("invalid StillGoodDude length")]
    InvalidStillGoodDudeLength,

    /// DATA меньше минимального
    /// DATA header.
    #[error("invalid DATA length")]
    InvalidDataLength,

    /// DATA payload слишком большой.
    #[error("DATA payload is too large")]
    DataPayloadTooLarge,

    /// PING имеет неправильный размер.
    #[error("invalid PING length")]
    InvalidPingLength,

    /// PONG имеет неправильный размер.
    #[error("invalid PONG length")]
    InvalidPongLength,

    #[error("PAYPHONE auth token is missing")]
    MissingAuthToken,

    #[error("invalid PAYPHONE auth token length")]
    InvalidAuthTokenLength,

    #[error("PAYPHONE auth token is too large")]
    AuthTokenTooLarge,

    #[error("invalid AccessDeniedDude length")]
    InvalidAccessDeniedDudeLength,

    #[error("unknown access deny reason: {0}")]
    UnknownDenyReason(u8),
}

//
// =============================================================
// u8 -> FrameType
// =============================================================
//

/// Превращает byte из wire protocol
/// в понятный Rust enum.
///
/// Например:
///
/// 1 -> FrameType::Data
///
/// 8 -> FrameType::BackAgainDude
impl TryFrom<u8> for FrameType {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(FrameType::Data),

            2 => Ok(FrameType::WhatsUpDude),

            3 => Ok(FrameType::AllGoodDude),

            4 => Ok(FrameType::Ping),

            5 => Ok(FrameType::Pong),

            6 => Ok(FrameType::Rekey),

            7 => Ok(FrameType::Close),

            8 => Ok(FrameType::BackAgainDude),

            9 => Ok(FrameType::StillGoodDude),

            10 => Ok(FrameType::AccessDeniedDude),

            _ => Err(FrameError::UnknownFrameType(value)),
        }
    }
}

//
// =============================================================
// PAYPHONE FRAME
// =============================================================
//

/// Главная единица PAYPHONE wire protocol.
///
/// Любое сообщение PAYPHONE
/// находится внутри Frame.
///
/// Например:
///
/// Frame {
///     version: 1,
///     frame_type: Data,
///     flags: 0,
///     sequence: 3,
///     payload: ...
/// }
#[derive(Debug, Clone)]
pub struct Frame {
    /// PAYPHONE protocol version.
    pub version: u8,

    /// Тип payload.
    pub frame_type: FrameType,

    /// Дополнительные bit flags.
    ///
    /// Пока:
    ///
    /// 0
    pub flags: u16,

    /// Порядковый номер Frame.
    pub sequence: u64,

    /// Вложенное PAYPHONE message.
    pub payload: Bytes,
}

//
// =============================================================
// FRAME IMPLEMENTATION
// =============================================================
//

impl Frame {
    /// Frame -> bytes.
    ///
    /// То есть:
    ///
    /// Rust struct
    ///
    /// ->
    ///
    /// wire representation.
    pub fn encode(&self) -> Bytes {
        let payload_len = self.payload.len();

        //
        // Создаём изменяемый buffer.
        //
        let mut buffer = BytesMut::with_capacity(HEADER_SIZE + payload_len);

        //
        // BYTE 0
        //
        // PAYPHONE version.
        //
        buffer.put_u8(self.version);

        //
        // BYTE 1
        //
        // FrameType enum
        //
        // ->
        //
        // обычный u8.
        //
        buffer.put_u8(self.frame_type as u8);

        //
        // BYTE 2-3
        //
        // flags.
        //
        buffer.put_u16(self.flags);

        //
        // BYTE 4-7
        //
        // payload length.
        //
        buffer.put_u32(payload_len as u32);

        //
        // BYTE 8-15
        //
        // Frame sequence.
        //
        buffer.put_u64(self.sequence);

        //
        // BYTE 16...
        //
        // Payload.
        //
        buffer.extend_from_slice(&self.payload);

        buffer.freeze()
    }

    /// bytes -> Frame.
    pub fn decode(mut buffer: Bytes) -> Result<Self, FrameError> {
        //
        // Минимально должно быть
        // хотя бы 16 bytes.
        //
        if buffer.len() < HEADER_SIZE {
            return Err(FrameError::TooSmall);
        }

        //
        // BYTE 0
        //
        let version = buffer.get_u8();

        //
        // Проверяем версию.
        //
        if version != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }

        //
        // BYTE 1
        //
        let frame_type_byte = buffer.get_u8();

        let frame_type = FrameType::try_from(frame_type_byte)?;

        //
        // BYTE 2-3
        //
        let flags = buffer.get_u16();

        //
        // BYTE 4-7
        //
        let payload_len = buffer.get_u32() as usize;

        //
        // BYTE 8-15
        //
        let sequence = buffer.get_u64();

        //
        // Один QUIC DATAGRAM
        // содержит ровно один
        // PAYPHONE Frame.
        //
        // Поэтому количество
        // оставшихся bytes
        // обязано ТОЧНО совпадать
        // с payload_len.
        //
        if payload_len != buffer.remaining() {
            return Err(FrameError::InvalidPayloadLength);
        }

        //
        // Ограничение размера.
        //
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge);
        }

        //
        // Забираем payload.
        //
        let payload = buffer.copy_to_bytes(payload_len);

        Ok(Self {
            version,
            frame_type,
            flags,
            sequence,
            payload,
        })
    }

    /// Удобный вариант decode
    /// для обычного &[u8].
    ///
    /// Старый UDP transport
    /// использовал этот метод.
    ///
    /// Он также удобен в тестах.
    pub fn decode_slice(data: &[u8]) -> Result<Self, FrameError> {
        Self::decode(Bytes::copy_from_slice(data))
    }
}

//
// =============================================================
// TESTS
// =============================================================
//

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        all_good_dude::AllGoodDude,
        back_again_dude::BackAgainDude,
        data::Data,
        ping::Ping,
        pong::Pong,
        still_good_dude::StillGoodDude,
        whats_up_dude::{CAP_DNS, CAP_IPV4, CAP_IPV6, WhatsUpDude},
    };

    // =========================================================
    // FRAME ROUNDTRIP
    // =========================================================

    #[test]
    fn frame_roundtrip() {
        let original = Frame {
            version: PROTOCOL_VERSION,

            frame_type: FrameType::Data,

            flags: 0,

            sequence: 42,

            payload: Bytes::from_static(b"hello payphone"),
        };

        //
        // Frame -> bytes.
        //
        let encoded = original.encode();

        //
        // bytes -> Frame.
        //
        let decoded = Frame::decode(encoded).expect("Frame decode failed");

        assert_eq!(decoded.version, PROTOCOL_VERSION);

        assert_eq!(decoded.frame_type, FrameType::Data);

        assert_eq!(decoded.flags, 0);

        assert_eq!(decoded.sequence, 42);

        assert_eq!(decoded.payload, Bytes::from_static(b"hello payphone"));
    }

    // =========================================================
    // UNKNOWN FRAME TYPE
    // =========================================================

    #[test]
    fn unknown_frame_type_fails() {
        let result = FrameType::try_from(99);

        assert!(result.is_err());
    }

    // =========================================================
    // SMALL FRAME
    // =========================================================

    #[test]
    fn small_frame_fails() {
        let data = Bytes::from_static(&[1, 2, 3]);

        let result = Frame::decode(data);

        assert!(result.is_err());
    }

    // =========================================================
    // WRONG PROTOCOL VERSION
    // =========================================================

    #[test]
    fn unsupported_version_fails() {
        //
        // Создаём валидный Frame.
        //
        let frame = Frame {
            version: 99,

            frame_type: FrameType::Ping,

            flags: 0,

            sequence: 1,

            payload: Bytes::new(),
        };

        let encoded = frame.encode();

        let result = Frame::decode(encoded);

        assert!(matches!(result, Err(FrameError::UnsupportedVersion(99))));
    }

    // =========================================================
    // WHATS UP DUDE INSIDE FRAME
    // =========================================================

    #[test]
    fn whats_up_dude_inside_frame_roundtrip() {
        let message = WhatsUpDude::new(
            1,
            CAP_IPV4 | CAP_IPV6 | CAP_DNS,
            Bytes::from_static(b"test-token"),
        );

        let frame = Frame {
            version: PROTOCOL_VERSION,

            frame_type: FrameType::WhatsUpDude,

            flags: 0,

            sequence: 1,

            payload: message.encode(),
        };

        let network = frame.encode();

        let decoded_frame = Frame::decode(network).expect("Frame decode failed");

        assert_eq!(decoded_frame.frame_type, FrameType::WhatsUpDude);

        let decoded_message =
            WhatsUpDude::decode(decoded_frame.payload).expect("WhatsUpDude decode failed");

        assert_eq!(decoded_message.protocol_version, PROTOCOL_VERSION);

        assert_eq!(decoded_message.client_version, 1);

        assert!(decoded_message.supports(CAP_IPV4));

        assert!(decoded_message.supports(CAP_IPV6));

        assert!(decoded_message.supports(CAP_DNS));
    }

    // =========================================================
    // ALL GOOD DUDE INSIDE FRAME
    // =========================================================

    #[test]
    fn all_good_dude_inside_frame_roundtrip() {
        let message = AllGoodDude::new([10, 77, 0, 2], 1280, 13);

        let original_session_id = message.session_id;

        let frame = Frame {
            version: PROTOCOL_VERSION,

            frame_type: FrameType::AllGoodDude,

            flags: 0,

            sequence: 2,

            payload: message.encode(),
        };

        let network = frame.encode();

        let decoded_frame = Frame::decode(network).expect("Frame decode failed");

        assert_eq!(decoded_frame.frame_type, FrameType::AllGoodDude);

        let decoded =
            AllGoodDude::decode(decoded_frame.payload).expect("AllGoodDude decode failed");

        assert_eq!(decoded.assigned_ipv4, [10, 77, 0, 2,]);

        assert_eq!(decoded.mtu, 1280);

        assert_eq!(decoded.session_id, original_session_id);
    }

    // =========================================================
    // DATA INSIDE FRAME
    // =========================================================

    #[test]
    fn data_inside_frame_roundtrip() {
        let session_id = [9u8; 16];

        let data = Data::new(session_id, 1, Bytes::from_static(b"Hello through PAYPHONE"));

        let frame = Frame {
            version: PROTOCOL_VERSION,

            frame_type: FrameType::Data,

            flags: 0,

            sequence: 3,

            payload: data.encode(),
        };

        let network = frame.encode();

        let decoded_frame = Frame::decode(network).expect("Frame decode failed");

        assert_eq!(decoded_frame.frame_type, FrameType::Data);

        let decoded_data = Data::decode(decoded_frame.payload).expect("DATA decode failed");

        assert_eq!(decoded_data.session_id, session_id);

        assert_eq!(decoded_data.packet_id, 1);

        assert_eq!(
            decoded_data.payload,
            Bytes::from_static(b"Hello through PAYPHONE")
        );
    }

    // =========================================================
    // PING INSIDE FRAME
    // =========================================================

    #[test]
    fn ping_inside_frame_roundtrip() {
        let ping = Ping::new([1u8; 16], 55);

        let frame = Frame {
            version: PROTOCOL_VERSION,

            frame_type: FrameType::Ping,

            flags: 0,

            sequence: 5,

            payload: ping.encode(),
        };

        let decoded_frame = Frame::decode(frame.encode()).unwrap();

        let decoded_ping = Ping::decode(decoded_frame.payload).unwrap();

        assert_eq!(decoded_ping.ping_id, 55);

        assert_eq!(decoded_ping.session_id, [1u8; 16]);
    }

    // =========================================================
    // PONG INSIDE FRAME
    // =========================================================

    #[test]
    fn pong_inside_frame_roundtrip() {
        let pong = Pong::new([2u8; 16], 99);

        let frame = Frame {
            version: PROTOCOL_VERSION,

            frame_type: FrameType::Pong,

            flags: 0,

            sequence: 6,

            payload: pong.encode(),
        };

        let decoded_frame = Frame::decode(frame.encode()).unwrap();

        let decoded_pong = Pong::decode(decoded_frame.payload).unwrap();

        assert_eq!(decoded_pong.ping_id, 99);

        assert_eq!(decoded_pong.session_id, [2u8; 16]);
    }

    // =========================================================
    // BACK AGAIN DUDE INSIDE FRAME
    // =========================================================

    #[test]
    fn back_again_dude_inside_frame_roundtrip() {
        let session_id = [3u8; 16];

        let resume_token = [4u8; 32];

        let message = BackAgainDude::new(session_id, resume_token);

        let frame = Frame {
            version: PROTOCOL_VERSION,

            frame_type: FrameType::BackAgainDude,

            flags: 0,

            sequence: 1,

            payload: message.encode(),
        };

        let decoded_frame = Frame::decode(frame.encode()).expect("Frame decode failed");

        assert_eq!(decoded_frame.frame_type, FrameType::BackAgainDude);

        let decoded =
            BackAgainDude::decode(decoded_frame.payload).expect("BackAgainDude decode failed");

        assert_eq!(decoded.session_id, session_id);

        assert_eq!(decoded.resume_token, resume_token);
    }

    // =========================================================
    // STILL GOOD DUDE INSIDE FRAME
    // =========================================================

    #[test]
    fn still_good_dude_inside_frame_roundtrip() {
        let message = StillGoodDude::new([5u8; 16], [10, 77, 0, 2], 1280, 13);

        let frame = Frame {
            version: PROTOCOL_VERSION,

            frame_type: FrameType::StillGoodDude,

            flags: 0,

            sequence: 2,

            payload: message.encode(),
        };

        let decoded_frame = Frame::decode(frame.encode()).expect("Frame decode failed");

        assert_eq!(decoded_frame.frame_type, FrameType::StillGoodDude);

        let decoded =
            StillGoodDude::decode(decoded_frame.payload).expect("StillGoodDude decode failed");

        assert_eq!(decoded.session_id, [5u8; 16]);

        assert_eq!(decoded.assigned_ipv4, [10, 77, 0, 2,]);

        assert_eq!(decoded.mtu, 1280);

        assert_eq!(decoded.capabilities, 13);
    }
}
