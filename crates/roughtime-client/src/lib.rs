//! Roughtime client library: UDP query + response verification.
//!
//! Designed to be used as a library dependency by diagnostic tools,
//! not just the CLI. Provides single queries, chained queries (for
//! online UDS mode), and parallel queries (for offline bag creation).

pub mod client;
pub mod request;
pub mod verify;

pub use client::{
    query_all, query_chained, query_server, query_server_with_nonce, ChainedResult, ClientError,
    ServerConfig, VerifiedResponse,
};
pub use verify::{extract_time, verify_response, verify_response_signatures_only, VerifyError};
