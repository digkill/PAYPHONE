use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::FrameError;

/// reason     = 1 byte
/// expires_at = 8 bytes
///
/// TOTAL = 9 bytes
pub const ACCESS_DENIED_DUDE_SIZE: usize = 9;

// =============================================================
// DENY REASON
// =============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DenyReason {
    InvalidToken = 1,

    SubscriptionExpired = 2,

    TokenRevoked = 3,

    SubscriptionNotActive = 4,

    UnknownSigningKey = 5,

    UnsupportedPlan = 6,

    InternalAuthError = 7,
}

impl TryFrom<u8> for DenyReason {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::InvalidToken),

            2 => Ok(Self::SubscriptionExpired),

            3 => Ok(Self::TokenRevoked),

            4 => Ok(Self::SubscriptionNotActive),

            5 => Ok(Self::UnknownSigningKey),

            6 => Ok(Self::UnsupportedPlan),

            7 => Ok(Self::InternalAuthError),

            _ => Err(FrameError::UnknownDenyReason(value)),
        }
    }
}

// =============================================================
// ACCESS DENIED DUDE
// =============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDeniedDude {
    /// Почему сервер отказал.
    pub reason: DenyReason,

    /// Если причина связана
    /// со сроком подписки,
    /// сервер возвращает expires_at.
    ///
    /// В остальных случаях:
    ///
    /// 0
    pub expires_at: u64,
}

impl AccessDeniedDude {
    pub fn new(reason: DenyReason, expires_at: u64) -> Self {
        Self { reason, expires_at }
    }

    pub fn encode(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(ACCESS_DENIED_DUDE_SIZE);

        buffer.put_u8(self.reason as u8);

        buffer.put_u64(self.expires_at);

        buffer.freeze()
    }

    pub fn decode(mut buffer: Bytes) -> Result<Self, FrameError> {
        if buffer.len() != ACCESS_DENIED_DUDE_SIZE {
            return Err(FrameError::InvalidAccessDeniedDudeLength);
        }

        let reason = DenyReason::try_from(buffer.get_u8())?;

        let expires_at = buffer.get_u64();

        Ok(Self { reason, expires_at })
    }
}

// =============================================================
// TESTS
// =============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_denied_roundtrip() {
        let original = AccessDeniedDude::new(DenyReason::SubscriptionExpired, 1_800_000_000);

        let encoded = original.encode();

        assert_eq!(encoded.len(), ACCESS_DENIED_DUDE_SIZE);

        let decoded = AccessDeniedDude::decode(encoded).unwrap();

        assert_eq!(decoded.reason, DenyReason::SubscriptionExpired);

        assert_eq!(decoded.expires_at, 1_800_000_000);
    }
}
