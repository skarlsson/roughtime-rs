/// TimeBag CBOR format: serialize/deserialize with magic prefix.

use serde::{Deserialize, Serialize};

/// Magic header for time bag files: "RTBAG" + version byte.
pub const BAG_MAGIC: &[u8; 6] = b"RTBAG\x01";

/// Current bag format version.
pub const BAG_VERSION: u32 = 1;

/// Error type for bag operations.
#[derive(Debug)]
pub enum BagError {
    /// Invalid magic header.
    BadMagic,
    /// CBOR deserialization error.
    Cbor(String),
    /// Client query error.
    Client(roughtime_client::ClientError),
    /// Not enough proofs collected.
    InsufficientProofs { got: usize, need: usize },
}

impl std::fmt::Display for BagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BagError::BadMagic => write!(f, "invalid bag magic header"),
            BagError::Cbor(e) => write!(f, "CBOR error: {e}"),
            BagError::Client(e) => write!(f, "client error: {e}"),
            BagError::InsufficientProofs { got, need } => {
                write!(f, "insufficient proofs: got {got}, need {need}")
            }
        }
    }
}

impl std::error::Error for BagError {}

impl From<roughtime_client::ClientError> for BagError {
    fn from(e: roughtime_client::ClientError) -> Self {
        BagError::Client(e)
    }
}

/// A time bag containing multiple Roughtime proofs.
#[derive(Debug, Serialize, Deserialize)]
pub struct TimeBag {
    /// Format version (currently 1).
    pub v: u32,
    /// Unix seconds when the bag was created.
    pub created: u64,
    /// 32-byte initial nonce if this is a chained bag, absent if independent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_nonce: Option<serde_bytes::ByteBuf>,
    /// Server metadata.
    pub servers: Vec<BagServer>,
    /// Raw Roughtime response proofs (in chain order if chained).
    pub proofs: Vec<BagProof>,
}

/// Server metadata within a time bag.
#[derive(Debug, Serialize, Deserialize)]
pub struct BagServer {
    /// Human-readable server name.
    pub name: String,
    /// 32-byte Ed25519 public key.
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
}

/// A single Roughtime proof within a time bag.
#[derive(Debug, Serialize, Deserialize)]
pub struct BagProof {
    /// Index into the `servers` array.
    pub server_idx: u32,
    /// Raw Roughtime response bytes.
    #[serde(with = "serde_bytes")]
    pub response: Vec<u8>,
    /// Extracted midpoint (Unix seconds) — for display, not security-critical.
    pub midpoint: u64,
    /// Extracted uncertainty radius (seconds) — for display, not security-critical.
    pub radius: u32,
}

impl TimeBag {
    /// Serialize the time bag to bytes with the magic prefix.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(BAG_MAGIC);
        ciborium::into_writer(self, &mut buf).expect("CBOR serialization failed");
        buf
    }

    /// Deserialize a time bag from bytes (expects magic prefix).
    pub fn from_bytes(data: &[u8]) -> Result<Self, BagError> {
        if data.len() < BAG_MAGIC.len() || &data[..BAG_MAGIC.len()] != BAG_MAGIC {
            return Err(BagError::BadMagic);
        }
        let cbor_data = &data[BAG_MAGIC.len()..];
        ciborium::from_reader(cbor_data).map_err(|e| BagError::Cbor(e.to_string()))
    }

    /// Whether this bag uses chained nonces (online mode).
    pub fn is_chained(&self) -> bool {
        self.initial_nonce.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bag_roundtrip() {
        let bag = TimeBag {
            v: BAG_VERSION,
            created: 1700000000,
            initial_nonce: None,
            servers: vec![BagServer {
                name: "TestServer".to_string(),
                pubkey: vec![0xAA; 32],
            }],
            proofs: vec![BagProof {
                server_idx: 0,
                response: vec![0xBB; 100],
                midpoint: 1700000000,
                radius: 5,
            }],
        };

        let bytes = bag.to_bytes();
        assert_eq!(&bytes[..6], BAG_MAGIC);

        let parsed = TimeBag::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.v, BAG_VERSION);
        assert_eq!(parsed.created, 1700000000);
        assert!(!parsed.is_chained());
        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].name, "TestServer");
        assert_eq!(parsed.proofs.len(), 1);
        assert_eq!(parsed.proofs[0].midpoint, 1700000000);
    }

    #[test]
    fn chained_bag_roundtrip() {
        let nonce = vec![0x42u8; 32];
        let bag = TimeBag {
            v: BAG_VERSION,
            created: 1700000000,
            initial_nonce: Some(serde_bytes::ByteBuf::from(nonce.clone())),
            servers: vec![
                BagServer {
                    name: "Server1".to_string(),
                    pubkey: vec![0xAA; 32],
                },
                BagServer {
                    name: "Server2".to_string(),
                    pubkey: vec![0xBB; 32],
                },
            ],
            proofs: vec![
                BagProof {
                    server_idx: 0,
                    response: vec![0xCC; 200],
                    midpoint: 1700000000,
                    radius: 3,
                },
                BagProof {
                    server_idx: 1,
                    response: vec![0xDD; 200],
                    midpoint: 1700000001,
                    radius: 4,
                },
            ],
        };

        let bytes = bag.to_bytes();
        let parsed = TimeBag::from_bytes(&bytes).unwrap();
        assert!(parsed.is_chained());
        assert_eq!(parsed.initial_nonce.unwrap().as_ref(), &nonce[..]);
        assert_eq!(parsed.proofs.len(), 2);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = vec![0u8; 100];
        bytes[..5].copy_from_slice(b"XXXXX");
        assert!(TimeBag::from_bytes(&bytes).is_err());
    }
}
