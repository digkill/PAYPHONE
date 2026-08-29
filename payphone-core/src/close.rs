use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{FrameError, all_good_dude::SESSION_ID_SIZE};

/// session_id = 16
/// reason     = 1
///
/// TOTAL = 17
pub const CLOSE_SIZE: usize = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseReason {
    /// Client is leaving on purpose (Ctrl+C).
    ClientShutdown = 0,

    /// Server is going away.
    ServerShutdown = 1,

    /// Another device took this subscription slot.
    Replaced = 2,
}

impl TryFrom<u8> for CloseReason {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ClientShutdown),
            1 => Ok(Self::ServerShutdown),
            2 => Ok(Self::Replaced),
            _ => Err(FrameError::UnknownCloseReason(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Close {
    pub session_id: [u8; SESSION_ID_SIZE],

    pub reason: CloseReason,
}

impl Close {
    pub fn new(session_id: [u8; SESSION_ID_SIZE], reason: CloseReason) -> Self {
        Self {
            session_id,
            reason,
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(CLOSE_SIZE);

        buffer.extend_from_slice(&self.session_id);

        buffer.put_u8(self.reason as u8);

        buffer.freeze()
    }

    pub fn decode(mut buffer: Bytes) -> Result<Self, FrameError> {
        if buffer.len() != CLOSE_SIZE {
            return Err(FrameError::InvalidCloseLength);
        }

        let mut session_id = [0u8; SESSION_ID_SIZE];

        buffer.copy_to_slice(&mut session_id);

        let reason = CloseReason::try_from(buffer.get_u8())?;

        Ok(Self {
            session_id,
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_roundtrip() {
        let original = Close::new([9u8; 16], CloseReason::ClientShutdown);

        let encoded = original.encode();

        assert_eq!(encoded.len(), CLOSE_SIZE);

        let decoded = Close::decode(encoded).expect("CLOSE decode failed");

        assert_eq!(decoded.session_id, [9u8; 16]);

        assert_eq!(decoded.reason, CloseReason::ClientShutdown);
    }
}
