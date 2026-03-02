/// IETF Roughtime framing (12-byte header).
///
/// Frame format: "ROUGHTIM" (8 bytes) || length (4 bytes LE) || payload

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::message::WireError;

/// Magic header bytes for IETF Roughtime frames.
pub const FRAME_MAGIC: &[u8; 8] = b"ROUGHTIM";

/// Minimum frame size: 8 (magic) + 4 (length).
pub const FRAME_HEADER_SIZE: usize = 12;

/// Wrap a message payload in an IETF Roughtime frame.
#[cfg(feature = "alloc")]
pub fn encode_framed(msg: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + msg.len());
    buf.extend_from_slice(FRAME_MAGIC);
    buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    buf.extend_from_slice(msg);
    buf
}

/// Strip the IETF Roughtime frame header and return the payload.
pub fn decode_framed(data: &[u8]) -> Result<&[u8], WireError> {
    if data.len() < FRAME_HEADER_SIZE {
        return Err(WireError::TooShort);
    }
    if &data[..8] != FRAME_MAGIC.as_slice() {
        return Err(WireError::BadFraming);
    }
    let len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if data.len() < FRAME_HEADER_SIZE + len {
        return Err(WireError::TooShort);
    }
    Ok(&data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let payload = b"hello world!"; // 12 bytes, 4-byte aligned
        let framed = encode_framed(payload);
        assert_eq!(framed.len(), FRAME_HEADER_SIZE + payload.len());
        assert_eq!(&framed[..8], b"ROUGHTIM");

        let decoded = decode_framed(&framed).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut framed = encode_framed(b"test");
        framed[0] = b'X';
        assert_eq!(decode_framed(&framed), Err(WireError::BadFraming));
    }

    #[test]
    fn truncated_frame_rejected() {
        let framed = encode_framed(b"test data!!!");
        // Truncate to just the header
        assert_eq!(
            decode_framed(&framed[..FRAME_HEADER_SIZE]),
            Err(WireError::TooShort)
        );
    }

    #[test]
    fn too_short_rejected() {
        assert_eq!(decode_framed(&[0u8; 6]), Err(WireError::TooShort));
    }
}
