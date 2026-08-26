use bytes::{Buf, BufMut, Bytes, BytesMut};

use rand::RngCore;

use crate::{FrameError, PROTOCOL_VERSION};

//
// Размер client nonce.
//
// 32 bytes = 256 bits.
//
pub const CLIENT_NONCE_SIZE: usize = 32;

//
// Размер сообщения WhatsUpDude.
//
// protocol_version = 1 byte
// client_version   = 2 bytes
// capabilities     = 4 bytes
// client_nonce     = 32 bytes
//
// Итого:
//
// 1 + 2 + 4 + 32 = 39 bytes
//
pub const WHATS_UP_DUDE_SIZE: usize = 39;

//
// CAP = capability.
//
// Capability означает:
//
// "какую функцию поддерживает клиент".
//
// Каждый capability занимает один бит
// внутри числа u32.
//

//
// BIT 0
//
// IPv4 support.
//
// Двоично:
//
// 00001
//
pub const CAP_IPV4: u32 = 1 << 0;

//
// BIT 1
//
// IPv6 support.
//
// 00010
//
pub const CAP_IPV6: u32 = 1 << 1;

//
// BIT 2
//
// PAYPHONE DNS support.
//
// 00100
//
pub const CAP_DNS: u32 = 1 << 2;

//
// BIT 3
//
// Возможность восстановить
// существующую Session.
//
pub const CAP_RESUME: u32 = 1 << 3;

//
// BIT 4
//
// Возможность продолжить Session
// после изменения сетевого пути.
//
pub const CAP_ROAMING: u32 = 1 << 4;

//
// Первое handshake-сообщение PAYPHONE.
//
// Клиент:
//
// "What's up, dude?"
//
// Сервер позже ответит:
//
// "All good, dude."
//
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhatsUpDude {
    //
    // Версия сетевого протокола.
    //
    // Сейчас:
    //
    // PAYPHONE/1
    //
    // поэтому:
    //
    // protocol_version = 1
    //
    pub protocol_version: u8,

    //
    // Версия самой клиентской программы.
    //
    // Это отдельная вещь.
    //
    // Например:
    //
    // PAYPHONE protocol = 1
    //
    // но программа клиента
    // может иметь версии:
    //
    // 1
    // 2
    // 3
    // 10
    //
    pub client_version: u16,

    //
    // Набор функций,
    // которые поддерживает клиент.
    //
    pub capabilities: u32,

    //
    // Случайные 32 bytes.
    //
    // Генерируются заново
    // при создании WhatsUpDude.
    //
    pub client_nonce: [u8; CLIENT_NONCE_SIZE],
}

impl WhatsUpDude {
    //
    // Создаём новое сообщение
    // "What's up, dude?"
    //
    pub fn new(client_version: u16, capabilities: u32) -> Self {
        //
        // Создаём массив из 32 нулей:
        //
        // 00 00 00 00 ...
        //
        let mut client_nonce = [0u8; CLIENT_NONCE_SIZE];

        //
        // Получаем генератор
        // случайных чисел.
        //
        let mut rng = rand::rng();

        //
        // Перезаписываем наши нули
        // случайными байтами.
        //
        rng.fill_bytes(&mut client_nonce);

        //
        // Возвращаем готовую структуру.
        //
        Self {
            protocol_version: PROTOCOL_VERSION,

            client_version,

            capabilities,

            client_nonce,
        }
    }

    //
    // Проверяем:
    //
    // поддерживает ли клиент
    // конкретную возможность.
    //
    pub fn supports(&self, capability: u32) -> bool {
        //
        // Побитовое AND.
        //
        // Например:
        //
        // capabilities:
        //
        // 00111
        //
        // CAP_IPV6:
        //
        // 00010
        //
        // AND:
        //
        // 00010
        //
        // Это НЕ 0.
        //
        // Значит IPv6 поддерживается.
        //
        self.capabilities & capability != 0
    }

    //
    // WhatsUpDude -> bytes
    //
    pub fn encode(&self) -> Bytes {
        //
        // Создаём буфер ровно
        // под наше сообщение.
        //
        let mut buffer = BytesMut::with_capacity(WHATS_UP_DUDE_SIZE);

        //
        // BYTE 0
        //
        // protocol_version
        //
        buffer.put_u8(self.protocol_version);

        //
        // BYTE 1-2
        //
        // client_version
        //
        buffer.put_u16(self.client_version);

        //
        // BYTE 3-6
        //
        // capabilities
        //
        buffer.put_u32(self.capabilities);

        //
        // BYTE 7-38
        //
        // client_nonce
        //
        buffer.extend_from_slice(&self.client_nonce);

        //
        // Возвращаем готовые bytes.
        //
        buffer.freeze()
    }

    //
    // bytes -> WhatsUpDude
    //
    pub fn decode(mut buffer: Bytes) -> Result<Self, FrameError> {
        //
        // Сообщение обязано
        // занимать ровно 39 bytes.
        //
        if buffer.len() != WHATS_UP_DUDE_SIZE {
            return Err(FrameError::InvalidWhatsUpDudeLength);
        }

        //
        // BYTE 0
        //
        let protocol_version = buffer.get_u8();

        //
        // BYTE 1-2
        //
        let client_version = buffer.get_u16();

        //
        // BYTE 3-6
        //
        let capabilities = buffer.get_u32();

        //
        // Создаём массив
        // для client_nonce.
        //
        let mut client_nonce = [0u8; CLIENT_NONCE_SIZE];

        //
        // После чтения:
        //
        // version
        // client_version
        // capabilities
        //
        // в buffer осталось ровно
        // 32 bytes.
        //
        // Копируем их в client_nonce.
        //
        buffer.copy_to_slice(&mut client_nonce);

        //
        // Возвращаем готовую структуру.
        //
        Ok(Self {
            protocol_version,
            client_version,
            capabilities,
            client_nonce,
        })
    }
}

//
// Тесты конкретно для WhatsUpDude.
//
#[cfg(test)]
mod tests {
    use super::*;

    //
    // Проверяем полный цикл:
    //
    // struct
    //   ↓
    // encode
    //   ↓
    // bytes
    //   ↓
    // decode
    //   ↓
    // struct
    //
    #[test]
    fn whats_up_dude_roundtrip() {
        let original = WhatsUpDude::new(1, CAP_IPV4 | CAP_IPV6 | CAP_DNS);

        //
        // Кодируем.
        //
        let encoded = original.encode();

        //
        // Размер обязан быть 39.
        //
        assert_eq!(encoded.len(), WHATS_UP_DUDE_SIZE);

        //
        // Декодируем.
        //
        let decoded = WhatsUpDude::decode(encoded).expect("WhatsUpDude decode failed");

        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);

        assert_eq!(decoded.client_version, 1);

        assert!(decoded.supports(CAP_IPV4));

        assert!(decoded.supports(CAP_IPV6));

        assert!(decoded.supports(CAP_DNS));

        //
        // Мы CAP_RESUME
        // не включали.
        //
        assert!(!decoded.supports(CAP_RESUME));

        //
        // Nonce после encode/decode
        // обязан остаться тем же.
        //
        assert_eq!(decoded.client_nonce, original.client_nonce);
    }

    //
    // Два новых сообщения
    // должны получить разные nonce.
    //
    #[test]
    fn whats_up_dude_nonce_is_random() {
        let first = WhatsUpDude::new(1, 0);

        let second = WhatsUpDude::new(1, 0);

        assert_ne!(first.client_nonce, second.client_nonce);
    }

    //
    // Проверяем неправильный размер.
    //
    #[test]
    fn invalid_size_fails() {
        //
        // Всего 3 bytes.
        //
        // Нам нужно 39.
        //
        let data = Bytes::from_static(&[1, 2, 3]);

        let result = WhatsUpDude::decode(data);

        assert!(result.is_err());
    }
}
