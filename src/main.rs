use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use clap::{Parser, Subcommand};

use roughtime_bag::{create_offline_bag, TimeBag};
use roughtime_client::ServerConfig;

#[derive(Parser)]
#[command(name = "roughtime-rs", about = "Roughtime client and time bag tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Query all configured Roughtime servers and display results.
    Query {
        /// Path to servers.toml configuration file.
        #[arg(long, default_value = "servers.toml")]
        servers: PathBuf,

        /// Timeout per server in seconds.
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },

    /// Create a time bag file from Roughtime server responses.
    Bag {
        /// Output file path.
        #[arg(short, long)]
        output: PathBuf,

        /// Path to servers.toml configuration file.
        #[arg(long, default_value = "servers.toml")]
        servers: PathBuf,

        /// Minimum number of proofs required.
        #[arg(long, default_value_t = 2)]
        min_proofs: usize,

        /// Timeout per server in seconds.
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },

    /// Display contents of a time bag file.
    BagInfo {
        /// Path to the bag file.
        file: PathBuf,
    },
}

/// Server entry as it appears in servers.toml.
#[derive(serde::Deserialize)]
struct ServerFile {
    server: Vec<ServerEntry>,
}

#[derive(serde::Deserialize)]
struct ServerEntry {
    name: String,
    address: String,
    public_key: String,
}

fn load_servers(path: &PathBuf) -> Result<Vec<ServerConfig>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let file: ServerFile = toml::from_str(&content)?;

    let engine = base64::engine::general_purpose::STANDARD;

    file.server
        .into_iter()
        .map(|entry| {
            let key_bytes = engine.decode(&entry.public_key)?;
            if key_bytes.len() != 32 {
                return Err(format!(
                    "server '{}': public key must be 32 bytes, got {}",
                    entry.name,
                    key_bytes.len()
                )
                .into());
            }
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&key_bytes);

            Ok(ServerConfig {
                name: entry.name,
                address: entry.address,
                public_key,
            })
        })
        .collect()
}

/// Format a Roughtime midpoint (seconds since Unix epoch) as a human-readable time.
///
/// IETF draft-14: MIDP is uint64 seconds since epoch.
/// Some older servers may still use the Google protocol (microseconds);
/// we detect this heuristically and convert.
fn format_time(midpoint: u64) -> String {
    // Heuristic: if midpoint > year 2200 in seconds, it's likely microseconds
    // (old Google protocol). Year 2200 ~ 7.26e9 seconds.
    let secs = if midpoint > 10_000_000_000 {
        (midpoint / 1_000_000) as i64
    } else {
        midpoint as i64
    };
    let dt = chrono::DateTime::from_timestamp(secs, 0);
    match dt {
        Some(d) => d.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("{midpoint} (invalid)"),
    }
}

/// Format a Roughtime radius for display.
///
/// IETF draft-14: RADI is uint32 seconds.
/// Old Google protocol: RADI is uint32 microseconds.
/// We detect the old format heuristically (values > 100_000 are likely microseconds).
fn format_radius(radius: u32, midpoint: u64) -> String {
    // If midpoint was detected as microseconds (old Google protocol),
    // radius is also in microseconds.
    if midpoint > 10_000_000_000 {
        let secs = radius as f64 / 1_000_000.0;
        format!("{secs:.1}s")
    } else {
        format!("{radius}s")
    }
}

fn cmd_query(servers_path: &PathBuf, timeout: Duration) {
    let servers = match load_servers(servers_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error loading servers: {e}");
            std::process::exit(1);
        }
    };

    println!(
        "{:<15} {:<25} {:>8} {:>8}",
        "SERVER", "TIME", "RADIUS", "RTT"
    );
    println!("{}", "-".repeat(60));

    let mut success = 0;
    for server in &servers {
        match roughtime_client::query_server(server, timeout) {
            Ok(resp) => {
                success += 1;
                println!(
                    "{:<15} {:<25} {:>8} {:>6.0}ms",
                    resp.server_name,
                    format_time(resp.midpoint),
                    format_radius(resp.radius, resp.midpoint),
                    resp.rtt.as_secs_f64() * 1000.0,
                );
            }
            Err(e) => {
                println!("{:<15} ERROR: {}", server.name, e);
            }
        }
    }

    println!();
    println!(
        "{success}/{} servers responded successfully.",
        servers.len()
    );
}

fn cmd_bag(output: &PathBuf, servers_path: &PathBuf, min_proofs: usize, timeout: Duration) {
    let servers = match load_servers(servers_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error loading servers: {e}");
            std::process::exit(1);
        }
    };

    println!("Querying {} servers...", servers.len());

    match create_offline_bag(&servers, min_proofs, timeout) {
        Ok(bag) => {
            let bytes = bag.to_bytes();
            if let Err(e) = fs::write(output, &bytes) {
                eprintln!("Error writing bag file: {e}");
                std::process::exit(1);
            }

            // Compute median time for display
            let mut midpoints: Vec<u64> = bag.proofs.iter().map(|p| p.midpoint).collect();
            midpoints.sort();
            let median = if midpoints.len() % 2 == 0 {
                (midpoints[midpoints.len() / 2 - 1] + midpoints[midpoints.len() / 2]) / 2
            } else {
                midpoints[midpoints.len() / 2]
            };

            println!("Bag created: {}", output.display());
            println!("  Proofs: {}", bag.proofs.len());
            println!("  Servers: {}", bag.servers.len());
            println!("  Median time: {}", format_time(median));
            println!("  File size: {} bytes", bytes.len());
        }
        Err(e) => {
            eprintln!("Error creating bag: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_bag_info(file: &PathBuf) {
    let data = match fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading file: {e}");
            std::process::exit(1);
        }
    };

    let bag = match TimeBag::from_bytes(&data) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error parsing bag: {e}");
            std::process::exit(1);
        }
    };

    let engine = base64::engine::general_purpose::STANDARD;

    println!("Time Bag: {}", file.display());
    println!("  Version: {}", bag.v);
    println!("  Created: {}", format_time(bag.created));
    println!(
        "  Mode: {}",
        if bag.is_chained() {
            "chained (online)"
        } else {
            "independent (offline)"
        }
    );

    if let Some(ref nonce) = bag.initial_nonce {
        println!("  Initial nonce: {}", hex::encode(nonce.as_ref()));
    }

    println!();
    println!("Servers ({}):", bag.servers.len());
    for (i, server) in bag.servers.iter().enumerate() {
        println!(
            "  [{}] {} (pubkey: {})",
            i,
            server.name,
            engine.encode(&server.pubkey)
        );
    }

    println!();
    println!("Proofs ({}):", bag.proofs.len());
    for (i, proof) in bag.proofs.iter().enumerate() {
        let server_name = bag
            .servers
            .get(proof.server_idx as usize)
            .map(|s| s.name.as_str())
            .unwrap_or("unknown");
        println!(
            "  [{}] server={} time={} radius={} ({} bytes)",
            i,
            server_name,
            format_time(proof.midpoint),
            format_radius(proof.radius, proof.midpoint),
            proof.response.len()
        );
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Query { servers, timeout } => {
            cmd_query(servers, Duration::from_secs(*timeout));
        }
        Commands::Bag {
            output,
            servers,
            min_proofs,
            timeout,
        } => {
            cmd_bag(output, servers, *min_proofs, Duration::from_secs(*timeout));
        }
        Commands::BagInfo { file } => {
            cmd_bag_info(file);
        }
    }
}
