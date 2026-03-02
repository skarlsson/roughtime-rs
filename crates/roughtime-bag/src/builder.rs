/// Build time bags by querying Roughtime servers.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use roughtime_client::{query_all, ChainedResult, ServerConfig};

use crate::format::{BagError, BagProof, BagServer, TimeBag, BAG_VERSION};

/// Create an offline bag (independent proofs, random nonces).
///
/// Queries all servers and collects at least `min_proofs` successful responses.
pub fn create_offline_bag(
    servers: &[ServerConfig],
    min_proofs: usize,
    timeout: Duration,
) -> Result<TimeBag, BagError> {
    let results = query_all(servers, timeout);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Build server list and proofs from successful queries
    let mut bag_servers = Vec::new();
    let mut bag_proofs = Vec::new();
    let mut server_index_map = std::collections::HashMap::new();

    for (i, result) in results.into_iter().enumerate() {
        if let Ok(resp) = result {
            let server_idx = if let Some(&idx) = server_index_map.get(&i) {
                idx
            } else {
                let idx = bag_servers.len() as u32;
                bag_servers.push(BagServer {
                    name: resp.server_name.clone(),
                    pubkey: servers[i].public_key.to_vec(),
                });
                server_index_map.insert(i, idx);
                idx
            };

            bag_proofs.push(BagProof {
                server_idx,
                response: resp.raw_response,
                midpoint: resp.midpoint,
                radius: resp.radius,
            });
        }
    }

    if bag_proofs.len() < min_proofs {
        return Err(BagError::InsufficientProofs {
            got: bag_proofs.len(),
            need: min_proofs,
        });
    }

    Ok(TimeBag {
        v: BAG_VERSION,
        created: now,
        initial_nonce: None,
        servers: bag_servers,
        proofs: bag_proofs,
    })
}

/// Create a chained bag from an existing ChainedResult.
///
/// Used when a diagnostic tool wants to save the chain it queried for an ECU.
pub fn create_chained_bag(initial_nonce: &[u8; 32], result: &ChainedResult) -> TimeBag {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut bag_servers = Vec::new();
    let mut bag_proofs = Vec::new();

    for (i, resp) in result.responses.iter().enumerate() {
        bag_servers.push(BagServer {
            name: resp.server_name.clone(),
            pubkey: result.server_keys[i].to_vec(),
        });

        bag_proofs.push(BagProof {
            server_idx: i as u32,
            response: resp.raw_response.clone(),
            midpoint: resp.midpoint,
            radius: resp.radius,
        });
    }

    TimeBag {
        v: BAG_VERSION,
        created: now,
        initial_nonce: Some(serde_bytes::ByteBuf::from(initial_nonce.to_vec())),
        servers: bag_servers,
        proofs: bag_proofs,
    }
}
