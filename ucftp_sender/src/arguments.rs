use std::{error::Error, ffi::OsString, path::PathBuf, str::FromStr};

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "scftp")]
#[command(arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Conditionally execute current command if the command of the provided
    /// session ID has not been executed or has failed
    #[arg(long)]
    unless: Option<u64>,
    /// Commands that must be executed before this one
    #[arg(long)]
    after: Option<Vec<u64>>,
}

/// Protocol capabilities
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Execute file
    // #[command(arg_required_else_help = true)]
    Run {
        /// Absolute path of the program to be executed
        path: String,
        /// Arguments of the program
        args: Option<Vec<String>>,
        /// Environment variables to set before executing the command. For this command only
        #[arg(value_parser = parse_key_val::<String, String>, last = true)]
        env: Option<Vec<(String, String)>>,
    },
    /// Execute command in default shell
    #[command(arg_required_else_help = true)]
    RunShell { command: String },
    /// Set environment variables
    #[command(arg_required_else_help = true)]
    SetEnv {
        /// A set of key-value pairs of the form KEY=VALUE
        #[arg(value_parser = parse_key_val::<String, String>, last = true)]
        env: Option<Vec<(String, String)>>,
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
        args: Option<Vec<String>>,
        /// Environment variables to set before exectuing the command. For this command only
        #[arg(value_parser = parse_key_val::<String, String>, last = true)]
        env: Option<Vec<(String, String)>>,
    },
    /// Create directory
    #[command(arg_required_else_help = true)]
    CreateDir { path: String, mode: CreateDirMode },
    /// Send a file
    #[command(arg_required_else_help = true)]
    SendFile {
        /// Path of the file to be sent
        local_path: PathBuf,
        /// Address or hostname of the remote
        remote: String,
        /// Path of the file in the remote
        remote_path: OsString,
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

/// Mode of appending to a file
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AppendMode {
    /// Append to existing or do nothing
    Append,
    /// Append or create
    AppendCreate,
}

/// Mode of deletion
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DeleteMode {
    /// Delete only if path is file
    File = 0,
    /// Delete only if path is empty directory
    EmptyDir,
    /// Path is a file or empty directory
    FileDir,
    /// Recursively delete directory
    Dir,
    /// Link
    Link,
    /// Any file system object, recursive for directories. If the object is a link,
    /// remove the link, not the object it points to
    Any,
}

/// Mode of file creation when sending
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CreateFileMode {
    /// Create or overwrite
    Overwrite = 0,
    /// Create or do nothing
    CreateNew,
    /// Create or rename existing and create
    RenameCreate,
}

/// Mode of creation: 0 - create or do nothing if exists, 1 - create or rename existing and create new
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CreateDirMode {
    /// Create or do nothing
    CreateNew = 0,
    /// Create or rename existing and create
    RenameCreate,
}

/// Mode of link creation
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CreateLinkMode {
    /// Create or overwrite
    Overwrite = 0,
    /// Create or do nothing
    CreateNew,
    /// Create or rename and create
    RenameCreate,
}

/// Type of the file system link
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LinkKind {
    /// Hard link
    H,
    /// Symbolic link
    S,
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
