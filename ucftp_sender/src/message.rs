use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

use crate::cli::Command;
use ucftp_shared::serialise::{BufSerialise, dump_le};

pub struct UnlessAfter {
    pub unless_session_id: Option<u64>,
    pub unless_wait: Option<u32>,
    pub after_session_ids: Vec<u64>,
    pub after_wait: Option<u32>,
}

/// Encode a protocol message, i.e. create a buffer containing the
/// serialised protocol message
pub fn serialise_message(command: &Command, ua: UnlessAfter) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1000);
    for _ in 0..8 {
        buf.push(0);
    }
    // Header
    encode_message_metadata(&mut buf, ua);

    // Body
    let mut com_enc = MessageCommandEncoder::new(buf);
    com_enc.encode_command(command);

    buf = com_enc.into_buf();
    // TODO(thesis): include this total message length
    let len_bytes = (buf.len() as u64).to_le_bytes();
    buf[..8].copy_from_slice(&len_bytes);
    buf
}

fn encode_message_metadata(buf: &mut Vec<u8>, ua: UnlessAfter) {
    let flags_idx = buf.len();
    // No extensions are defined, so they are ignored
    buf.push(0);
    if let Some(sid) = ua.unless_session_id {
        buf[flags_idx] |= 0b00000010;
        ua.unless_wait.unwrap_or(0).serialise_to_buf(buf);
        dump_le(buf, sid);
    }
    if !ua.after_session_ids.is_empty() {
        buf[flags_idx] |= 0b00000001;
        ua.after_wait.unwrap_or(0).serialise_to_buf(buf);
        (ua.after_session_ids.len() as u64).serialise_to_buf(buf);
        for sid in ua.after_session_ids {
            dump_le(buf, sid);
        }
    }
}

pub struct MessageCommandEncoder {
    buf: Vec<u8>,
}

impl MessageCommandEncoder {
    pub fn new(buf: Vec<u8>) -> MessageCommandEncoder {
        MessageCommandEncoder { buf }
    }

    pub fn into_buf(self) -> Vec<u8> {
        self.buf
    }

    fn read_file<P: AsRef<Path>>(&mut self, path: P) {
        // For now we will assume that the path exists
        let f = File::open(path).expect("Requested file does not exist");
        // File length
        let len = f.metadata().unwrap().len();
        len.serialise_to_buf(&mut self.buf);
        let mut reader = BufReader::new(f);
        reader.read_to_end(&mut self.buf).unwrap();
    }

    fn read_file_offset<P: AsRef<Path>>(&mut self, path: P, offset: u64) {
        // For now we will assume that the path exists and the offset is valid
        let f = File::open(path).expect("Requested file does not exist");
        let len = f.metadata().unwrap().len();
        let mut reader = BufReader::new(f);
        reader
            .seek_relative(offset as i64)
            .expect("Requested file is smaller than requested offset");
        // File length
        (len - offset).serialise_to_buf(&mut self.buf);
        reader.read_to_end(&mut self.buf).unwrap();
    }

    pub fn encode_command(&mut self, command: &Command) {
        self.buf.push(command.to_command_number());
        match command {
            Command::Run { path, args, env } => {
                path.serialise_to_buf(&mut self.buf);
                env.serialise_to_buf(&mut self.buf);
                args.serialise_to_buf(&mut self.buf);
            }
            Command::RunShell { command } => {
                command.serialise_to_buf(&mut self.buf);
            }
            Command::SetEnv { env } => {
                env.serialise_to_buf(&mut self.buf);
            }
            Command::RmEnv { env } => {
                env.serialise_to_buf(&mut self.buf);
            }
            Command::RunReceived { id, args, env } => {
                dump_le(&mut self.buf, *id);
                env.serialise_to_buf(&mut self.buf);
                args.serialise_to_buf(&mut self.buf);
            }
            Command::CreateDir { path, mode } => {
                path.serialise_to_buf(&mut self.buf);
                self.buf.push(*mode as u8);
            }
            Command::SendFile {
                local_path,
                remote_path,
                mode,
            } => {
                remote_path.serialise_to_buf(&mut self.buf);
                self.buf.push(*mode as u8);
                self.read_file(local_path);
            }
            Command::AppendToFile {
                local_path,
                offset,
                remote_path,
                mode,
            } => {
                remote_path.serialise_to_buf(&mut self.buf);
                self.buf.push(*mode as u8);
                if let Some(o) = offset {
                    self.read_file_offset(local_path, *o);
                } else {
                    self.read_file(local_path);
                }
            }
            Command::AppendToReceived {
                id,
                local_path,
                offset,
            } => {
                dump_le(&mut self.buf, *id);
                if let Some(o) = offset {
                    self.read_file_offset(local_path, *o);
                } else {
                    self.read_file(local_path);
                }
            }
            Command::Rename { from, to } => {
                from.serialise_to_buf(&mut self.buf);
                to.serialise_to_buf(&mut self.buf);
            }
            Command::Move { from, to } => {
                from.serialise_to_buf(&mut self.buf);
                to.serialise_to_buf(&mut self.buf);
            }
            Command::CreateLink {
                target,
                source,
                mode,
                kind,
            } => {
                target.serialise_to_buf(&mut self.buf);
                source.serialise_to_buf(&mut self.buf);
                self.buf.push((*mode as u8) << 4 | (*kind as u8));
            }
            Command::Delete { path, mode } => {
                path.serialise_to_buf(&mut self.buf);
                self.buf.push(*mode as u8);
            }
        }
    }
}
