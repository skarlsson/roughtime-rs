# roughtime-rs

Roughtime client library and CLI tool implementing the [IETF Roughtime protocol (draft-14)](https://www.ietf.org/archive/id/draft-ietf-ntp-roughtime-14.txt).

Queries public Roughtime servers to obtain cryptographically verified timestamps, and packages them into "time bags" for offline or online use.

## Crates

| Crate | Description |
|---|---|
| `roughtime-wire` | Wire format encode/decode. Zero-copy parser, message builder, IETF framing. `no_std` compatible. |
| `roughtime-client` | UDP client with Ed25519 signature verification, Merkle proof validation, and nonce chaining. Designed as a library for diagnostic tools. |
| `roughtime-bag` | CBOR-based "time bag" format for storing multiple signed Roughtime proofs. |

## Usage modes

### Online (chained queries)

For diagnostic tools bridging an ECU's nonce over UDS:

1. ECU generates a 32-byte nonce and sends it to the diagnostic tool
2. Diagnostic tool calls `query_chained()` with the ECU's nonce
3. Each server is queried sequentially: `nonce[0] = ecu_nonce`, `nonce[i+1] = SHA-256(response[i])`
4. Raw responses + server public keys are returned to the ECU
5. ECU verifies the chain, Merkle proofs, and Ed25519 signatures to prove freshness

### Offline (time bags)

For pre-recorded proofs loaded via USB or other media:

1. Tool queries servers with independent random nonces
2. Responses are packaged into a CBOR time bag file (`.bag`)
3. ECU verifies Ed25519 signatures only (no nonce binding)

## CLI

```
roughtime-rs query [--servers servers.toml] [--timeout 5]
```
Query all configured servers and display verified times.

```
roughtime-rs bag --output time.bag [--servers servers.toml] [--min-proofs 2] [--timeout 5]
```
Create a time bag file from server responses.

```
roughtime-rs bag-info <file.bag>
```
Display contents of a time bag file.

### Example output

```
$ roughtime-rs query
SERVER          TIME                        RADIUS      RTT
------------------------------------------------------------
int08h          2026-03-01 18:54:07 UTC       5.0s    113ms
```

## Library usage

Add `roughtime-client` as a dependency:

```toml
[dependencies]
roughtime-client = { git = "https://github.com/skarlsson/roughtime-rs.git" }
```

### Single server query

```rust
use roughtime_client::{query_server, ServerConfig};
use std::time::Duration;

let server = ServerConfig {
    name: "int08h".into(),
    address: "roughtime.int08h.com:2002".into(),
    public_key: /* 32-byte Ed25519 public key */,
};

let resp = query_server(&server, Duration::from_secs(5))?;
println!("Time: {} +/- {}s", resp.midpoint, resp.radius);
```

### Chained query (for UDS diagnostic tools)

```rust
use roughtime_client::{query_chained, ServerConfig};
use std::time::Duration;

// ECU provides a 32-byte nonce via UDS RoutineControl
let ecu_nonce: [u8; 32] = /* from ECU */;
let servers: Vec<ServerConfig> = /* load from config */;

let result = query_chained(&ecu_nonce, &servers, Duration::from_secs(5))?;

// Send back to ECU for verification:
let raw_responses = result.raw_responses(); // Vec<&[u8]>
let pubkeys = result.pubkeys();             // &[[u8; 32]]
```

## Server configuration

Servers are configured in `servers.toml`:

```toml
[[server]]
name = "int08h"
address = "roughtime.int08h.com:2002"
public_key = "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE="
```

Public keys are base64-encoded 32-byte Ed25519 keys.

## Time bag format

Bag files use a 6-byte magic header (`RTBAG\x01`) followed by a CBOR payload:

```
RTBAG\x01 || CBOR {
    v: 1,
    created: <unix seconds>,
    initial_nonce: <32 bytes, optional>,  // present for chained bags
    servers: [{ name, pubkey }],
    proofs: [{ server_idx, response, midpoint, radius }]
}
```

## Protocol notes

- Targets **IETF draft-14** where MIDP and RADI are in **seconds**
- Some older servers (e.g. int08h/roughenough) still use the original Google protocol where MIDP/RADI are in **microseconds** -- the CLI detects this heuristically for display
- Verification: Ed25519 delegation chain (long-term key signs DELE, delegated key signs SREP) + SHA-512 Merkle inclusion proof

## Building

```
cargo build
cargo test
```

## License

EPL-2.0
