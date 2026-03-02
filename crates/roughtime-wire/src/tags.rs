/// Roughtime protocol tag constants (IETF draft-14).
///
/// Tags are 4-byte little-endian values derived from ASCII strings.

pub const TAG_VER: u32 = 0x00524556; // "VER\0"
pub const TAG_NONC: u32 = 0x434E4F4E; // "NONC"
pub const TAG_CERT: u32 = 0x54524543; // "CERT"
pub const TAG_SIG: u32 = 0x00474953; // "SIG\0"
pub const TAG_SREP: u32 = 0x50455253; // "SREP"
pub const TAG_DELE: u32 = 0x454C4544; // "DELE"
pub const TAG_INDX: u32 = 0x58444E49; // "INDX"
pub const TAG_MIDP: u32 = 0x5044494D; // "MIDP"
pub const TAG_RADI: u32 = 0x49444152; // "RADI"
pub const TAG_ROOT: u32 = 0x544F4F52; // "ROOT"
pub const TAG_PATH: u32 = 0x48544150; // "PATH"
pub const TAG_PUBK: u32 = 0x4B425550; // "PUBK"
pub const TAG_MINT: u32 = 0x544E494D; // "MINT"
pub const TAG_MAXT: u32 = 0x5458414D; // "MAXT"
pub const TAG_ZZZZ: u32 = 0x5A5A5A5A; // "ZZZZ" (padding)
pub const TAG_PAD: u32 = 0xFF444150; // "PAD\xff"

/// IETF Roughtime draft-14 version number.
pub const VERSION_DRAFT14: u32 = 0x8000000E;

/// Signature context for DELE signatures (long-term key signs delegation).
pub const SIG_CONTEXT_DELE: &[u8] = b"RoughTime v1 delegation signature--\x00";

/// Signature context for SREP signatures (delegated key signs response).
pub const SIG_CONTEXT_SREP: &[u8] = b"RoughTime v1 response signature\x00";

/// Convert a tag value to its 4-byte ASCII representation for display.
pub fn tag_to_str(tag: u32) -> [u8; 4] {
    tag.to_le_bytes()
}
