use bytes::{Bytes, BytesMut};

use crate::{
    FrameError,
    all_good_dude::{SERVER_NONCE_SIZE, SESSION_ID_SIZE},
};

/// Client asks the server to rotate the resume token.
pub const REKEY_REQUEST_SIZE: usize = SESSION_ID_SIZE;

/// Server offer or client confirm: session_id + nonce.
pub const REKEY_TOKEN_SIZE: usize = SESSION_ID_SIZE + SERVER_NONCE_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rekey {
    Request {
        session_id: [u8; SESSION_ID_SIZE],
    },

    Token {
        session_id: [u8; SESSION_ID_SIZE],

        nonce: [u8; SERVER_NONCE_SIZE],
    },
}

impl Rekey {
    pub fn request(session_id: [u8; SESSION_ID_SIZE]) -> Self {
        Self::Request { session_id }
    }

    pub fn token(session_id: [u8; SESSION_ID_SIZE], nonce: [u8; SERVER_NONCE_SIZE]) -> Self {
        Self::Token { session_id, nonce }
    }

    pub fn session_id(&self) -> [u8; SESSION_ID_SIZE] {
        match *self {
            Self::Request { session_id } | Self::Token { session_id, .. } => session_id,
        }
    }

    pub fn encode(&self) -> Bytes {
        match self {
            Self::Request { session_id } => {
                let mut buffer = BytesMut::with_capacity(REKEY_REQUEST_SIZE);

                buffer.extend_from_slice(session_id);

                buffer.freeze()
            }

            Self::Token { session_id, nonce } => {
                let mut buffer = BytesMut::with_capacity(REKEY_TOKEN_SIZE);

                buffer.extend_from_slice(session_id);

                buffer.extend_from_slice(nonce);

                buffer.freeze()
            }
        }
    }

    pub fn decode(buffer: Bytes) -> Result<Self, FrameError> {
        match buffer.len() {
            REKEY_REQUEST_SIZE => {
                let mut session_id = [0u8; SESSION_ID_SIZE];

                session_id.copy_from_slice(&buffer);

                Ok(Self::Request { session_id })
            }

            REKEY_TOKEN_SIZE => {
                let mut session_id = [0u8; SESSION_ID_SIZE];

                session_id.copy_from_slice(&buffer[..SESSION_ID_SIZE]);

                let mut nonce = [0u8; SERVER_NONCE_SIZE];

                nonce.copy_from_slice(&buffer[SESSION_ID_SIZE..]);

                Ok(Self::Token { session_id, nonce })
            }

            _ => Err(FrameError::InvalidRekeyLength),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let original = Rekey::request([3u8; 16]);

        let decoded = Rekey::decode(original.encode()).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn token_roundtrip() {
        let original = Rekey::token([3u8; 16], [7u8; 32]);

        let decoded = Rekey::decode(original.encode()).unwrap();

        assert_eq!(decoded, original);
    }
}
