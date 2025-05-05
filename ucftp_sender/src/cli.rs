use std::{error::Error, net::Ipv4Addr, path::PathBuf, str::FromStr};

use clap::{Parser, Subcommand};
use ucftp_shared::{IP4_HEADER_SIZE, UDP_HEADER_SIZE, message::*};

const SAFE_IP4_PACKET_SIZE: u16 = 1280 - IP4_HEADER_SIZE - UDP_HEADER_SIZE;

/// Unidirectional Command and File Transfer Protocol CLI.
/// Send commands and data to a remote machine.
#[derive(Debug, Parser)]
#[command(name = "ucftp")]
#[command(arg_required_else_help = true)]
pub struct Cli {
    /// IPv4 address of the remote
    // #[clap(global = true)] // does not work with required args
    pub remote_ip: Ipv4Addr,
    #[command(subcommand)]
    pub command: Command,
    /// Conditionally execute current command if the command of the provided
    /// session ID has not been executed or has failed
    #[arg(long = "usid", short = 'u')]
    pub unless_session_id: Option<u64>,
    /// Time (in ms) to wait for command with provided session ID to be executed
    #[arg(long = "uwt", requires = "unless_session_id")]
    pub unless_wait: Option<u32>,
    /// Session IDs of commands that must be executed before this one
    #[arg(long = "asid", short = 'a')]
    pub after_session_ids: Vec<u64>,
    /// Time (in ms) to wait for other commands to be executed before executing
    /// this one
    #[arg(long = "awt", requires = "after_session_ids")]
    pub after_wait: Option<u32>,
    /// Packet size to use. IP + UDP headers included
    #[arg(short = 'p', default_value_t = SAFE_IP4_PACKET_SIZE)]
    pub packet_size: u16,
    /// Directory where the keys are stored. Key must be named sender_sk.pem
    /// sender_pk.pem for secret (private) and public keys respectively
    #[arg(short = 'k')]
    pub sender_keys_dir: Option<PathBuf>,
    /// File containing the receiver public key
    #[arg(short = 'r')]
    pub receiver_pk_file: Option<PathBuf>,
    /// Maximum transfer speed in kB/s
    #[arg(short = 's')]
    pub max_speed: Option<u32>,
    /// Use RaptorQ forward error correction
    #[arg(long, default_value_t = false)]
    pub fec: bool,
    /// Forward error correction overhead, % of regular packets
    #[arg(long = "fec-overhead", default_value_t = 10, requires = "fec")]
    pub fec_overhead_percent: u16,
}

/// Protocol capabilities
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Execute file
    #[command(arg_required_else_help = true)]
    Run {
        /// Absolute path of the program to be executed
        path: String,
        /// Arguments of the program
        #[arg(long, short)]
        args: Vec<String>,
        /// Environment variables to set before executing the command. For this command only
        #[arg(long, short, value_parser = parse_key_val::<String, String>)]
        env: Vec<(String, String)>,
    },
    /// Execute command in default shell
    #[command(arg_required_else_help = true)]
    RunShell { command: String },
    /// Set environment variables
    #[command(arg_required_else_help = true)]
    SetEnv {
        /// A set of key-value pairs of the form KEY=VALUE
        #[arg(value_parser = parse_key_val::<String, String>)]
        env: Vec<(String, String)>,
    },
    /// Remove environment variables
    #[command(arg_required_else_help = true)]
    RmEnv {
        /// A set of environment variable names to remove
        env: Vec<String>,
    },
    /// Execute file received via a specified transfer
    #[command(arg_required_else_help = true)]
    RunReceived {
        /// Session ID of the command that sent the file
        id: u64,
        /// Arguments of the program
        #[arg(long, short)]
        args: Vec<String>,
        /// Environment variables to set before exectuing the command. For this command only
        #[arg(long, short, value_parser = parse_key_val::<String, String>)]
        env: Vec<(String, String)>,
    },
    /// Create directory
    #[command(arg_required_else_help = true)]
    CreateDir { path: String, mode: CreateDirMode },
    /// Send a file
    #[command(arg_required_else_help = true)]
    SendFile {
        /// Path of the file to be sent
        local_path: PathBuf,
        /// Path of the file in the remote
        remote_path: String,
        mode: CreateFileMode,
    },
    /// Append to a file
    #[command(arg_required_else_help = true)]
    AppendToFile {
        /// Path of the file to be [partially] sent
        local_path: PathBuf,
        /// Offset from the start of the file to start reading from
        offset: Option<u64>,
        /// Path of the destination file
        remote_path: String,
        mode: AppendMode,
    },
    /// Append to file from specified transfer
    #[command(arg_required_else_help = true)]
    AppendToReceived {
        /// Session ID of the referenced file transfer
        id: u64,
        /// Path of the file to be [partially] sent
        local_path: PathBuf,
        /// Offset from the start of the file to start reading from
        offset: Option<u64>,
    },
    /// Rename a file system object (file, directory, link)
    #[command(arg_required_else_help = true)]
    Rename {
        /// Current absolute path
        from: String,
        /// New name (without path)
        to: String,
    },
    /// Move a file system object
    #[command(arg_required_else_help = true)]
    Move {
        /// Current absolute path
        from: String,
        /// New absolute path
        to: String,
    },
    /// Create a file system link
    #[command(arg_required_else_help = true)]
    CreateLink {
        /// Absolute path of the link target
        target: String,
        /// Absolute path of the link source
        source: String,
        mode: CreateLinkMode,
        kind: LinkKind,
    },
    /// Delete a file system object
    #[command(arg_required_else_help = true)]
    Delete {
        /// Path to object
        path: String,
        mode: DeleteMode,
    },
}

/// Parse a single key-value pair
fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

impl Command {
    pub fn to_command_number(&self) -> u8 {
        match self {
            Command::Run { .. } => 0,
            Command::RunShell { .. } => 1,
            Command::SetEnv { .. } => 2,
            Command::RmEnv { .. } => 3,
            Command::RunReceived { .. } => 4,
            Command::CreateDir { .. } => 5,
            Command::SendFile { .. } => 6,
            Command::AppendToFile { .. } => 7,
            Command::AppendToReceived { .. } => 8,
            Command::Rename { .. } => 9,
            Command::Move { .. } => 10,
            Command::CreateLink { .. } => 11,
            Command::Delete { .. } => 12,
        }
    }
}

// TODO: RaptorQ blocks are independent (i.e. can be encoded/decoded independently
// from each other). raptorq Rust lib only supports encoding/decoding all the
// blocks in one go. There is a max of 256 blocks during one encoding. RaptorQ
// by design cannot encode more than that, so the application has to do it by
// itself. EDIT: no need to do that, RaptorQ already uses sub-blocks that are
// kind of independent (at least they can be decoded independently). So manually
// splitting everything into blocks is redundant. The existing mode of putting
// all the data in one FEC "chunk" already works, just the API for decoding
// blocks and sub-blocks is not provided by Rust raptorq.
