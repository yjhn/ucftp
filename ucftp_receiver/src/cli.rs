use std::path::PathBuf;

use clap::Parser;

/// Unidirectional Command and File Transfer Protocol receiver daemon.
/// Continuously listens on UDP port 4321 for incoming commands
/// and executes them.
#[derive(Debug, Parser)]
#[command(name = "scftpd")]
pub struct Cli {
    /// Directory where the keys are stored. Key must be named sender_sk.pem
    /// sender_pk.pem for secret (private) and public keys respectively
    #[arg(short = 'k')]
    pub sender_keys_dir: Option<PathBuf>,
    /// File containing the receiver private key
    #[arg(short = 'r')]
    pub receiver_sk_file: Option<PathBuf>,
}
