//! Roughtime time bag: CBOR format for offline/chained proofs.
//!
//! Supports both offline (independent proofs with random nonces) and
//! online (chained proofs with initial nonce) modes.

pub mod builder;
pub mod format;

pub use builder::{create_chained_bag, create_offline_bag};
pub use format::{BagError, BagProof, BagServer, TimeBag, BAG_MAGIC, BAG_VERSION};
