/// UDP transport and high-level query functions for Roughtime.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::request::build_request;
use crate::verify::{verify_response, VerifyError};

/// Configuration for a Roughtime server.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServerConfig {
    pub name: String,
    pub address: String,
    pub public_key: [u8; 32],
}

/// A verified Roughtime response.
#[derive(Debug, Clone)]
pub struct VerifiedResponse {
    pub server_name: String,
    /// Time midpoint in seconds since Unix epoch (IETF draft-14).
    pub midpoint: u64,
    /// Uncertainty radius in seconds (IETF draft-14).
    pub radius: u32,
    /// Raw Roughtime response bytes (for bag or UDS return).
    pub raw_response: Vec<u8>,
    /// Nonce used for this query.
    pub nonce: [u8; 32],
    /// Network round-trip time.
    pub rtt: Duration,
}

/// Result of a chained query sequence.
#[derive(Debug, Clone)]
pub struct ChainedResult {
    pub responses: Vec<VerifiedResponse>,
    pub server_keys: Vec<[u8; 32]>,
}

impl ChainedResult {
    /// Extract raw response buffers (for sut_rt_verify_bag on ECU side).
    pub fn raw_responses(&self) -> Vec<&[u8]> {
        self.responses.iter().map(|r| r.raw_response.as_slice()).collect()
    }

    /// Extract server public keys in proof order.
    pub fn pubkeys(&self) -> &[[u8; 32]] {
        &self.server_keys
    }
}

/// Error type for client operations.
#[derive(Debug)]
pub enum ClientError {
    /// DNS resolution failed.
    DnsResolution(String),
    /// Network I/O error.
    Io(std::io::Error),
    /// Response verification failed.
    Verify(VerifyError),
    /// Request timed out.
    Timeout,
    /// Response too large.
    ResponseTooLarge,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::DnsResolution(addr) => write!(f, "DNS resolution failed for: {addr}"),
            ClientError::Io(e) => write!(f, "I/O error: {e}"),
            ClientError::Verify(e) => write!(f, "verification failed: {e}"),
            ClientError::Timeout => write!(f, "request timed out"),
            ClientError::ResponseTooLarge => write!(f, "response too large"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

impl From<VerifyError> for ClientError {
    fn from(e: VerifyError) -> Self {
        ClientError::Verify(e)
    }
}

/// Maximum response size we'll accept (2 KiB).
const MAX_RESPONSE_SIZE: usize = 2048;

/// Resolve a server address string to a SocketAddr.
fn resolve_address(address: &str) -> Result<SocketAddr, ClientError> {
    address
        .to_socket_addrs()
        .map_err(|_| ClientError::DnsResolution(address.to_string()))?
        .next()
        .ok_or_else(|| ClientError::DnsResolution(address.to_string()))
}

/// Query a single Roughtime server with a specific nonce.
///
/// Sends a UDP request, waits for a response, and verifies it.
pub fn query_server_with_nonce(
    server: &ServerConfig,
    nonce: &[u8; 32],
    timeout: Duration,
) -> Result<VerifiedResponse, ClientError> {
    let addr = resolve_address(&server.address)?;
    let request = build_request(nonce);

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(timeout))?;

    let start = Instant::now();
    socket.send_to(&request, addr)?;

    let mut buf = [0u8; MAX_RESPONSE_SIZE];
    let (len, _src) = socket.recv_from(&mut buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
            ClientError::Timeout
        } else {
            ClientError::Io(e)
        }
    })?;
    let rtt = start.elapsed();

    let response_bytes = &buf[..len];
    let verified = verify_response(response_bytes, nonce, &server.public_key)?;

    Ok(VerifiedResponse {
        server_name: server.name.clone(),
        midpoint: verified.midpoint,
        radius: verified.radius,
        raw_response: response_bytes.to_vec(),
        nonce: *nonce,
        rtt,
    })
}

/// Query a single Roughtime server with a random nonce.
pub fn query_server(
    server: &ServerConfig,
    timeout: Duration,
) -> Result<VerifiedResponse, ClientError> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    query_server_with_nonce(server, &nonce, timeout)
}

/// Perform a chained Roughtime query sequence seeded with an external nonce.
///
/// This is the primary API for diagnostic tools bridging ECU <-> Roughtime:
///   1. ECU generates nonce, sends to diagnostic tool over UDS
///   2. Diagnostic tool calls `query_chained(ecu_nonce, servers, ...)`
///   3. Sends `result.raw_responses()` + `result.pubkeys()` back to ECU
///   4. ECU calls `sut_rt_verify_bag()` with initial_nonce to verify chain
///
/// Nonce chaining: nonce[0] = initial_nonce,
///                 nonce[i+1] = SHA-256(raw_response[i])
pub fn query_chained(
    initial_nonce: &[u8; 32],
    servers: &[ServerConfig],
    timeout: Duration,
) -> Result<ChainedResult, ClientError> {
    let mut responses = Vec::with_capacity(servers.len());
    let mut server_keys = Vec::with_capacity(servers.len());
    let mut current_nonce = *initial_nonce;

    for server in servers {
        let resp = query_server_with_nonce(server, &current_nonce, timeout)?;

        // Next nonce = SHA-256(raw_response)
        let mut hasher = Sha256::new();
        hasher.update(&resp.raw_response);
        let hash = hasher.finalize();
        current_nonce.copy_from_slice(&hash);

        server_keys.push(server.public_key);
        responses.push(resp);
    }

    Ok(ChainedResult {
        responses,
        server_keys,
    })
}

/// Query multiple servers independently (random nonces, no chaining).
///
/// Used for offline time bag creation. Queries are performed sequentially.
pub fn query_all(
    servers: &[ServerConfig],
    timeout: Duration,
) -> Vec<Result<VerifiedResponse, ClientError>> {
    servers.iter().map(|s| query_server(s, timeout)).collect()
}
