//! Roughtime wire format encoding and decoding.
//!
//! This crate provides zero-copy parsing and building of Roughtime messages
//! as specified in IETF draft-roughtime-agl-14.
//!
//! It is `no_std` compatible (with the `alloc` feature for message building).

#![cfg_attr(not(feature = "alloc"), no_std)]

pub mod framing;
pub mod message;
pub mod tags;

pub use framing::{decode_framed, FRAME_HEADER_SIZE, FRAME_MAGIC};
pub use message::{Message, WireError};
pub use tags::*;

#[cfg(feature = "alloc")]
pub use framing::encode_framed;
#[cfg(feature = "alloc")]
pub use message::MessageBuilder;
