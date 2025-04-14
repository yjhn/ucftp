use clap::Parser;
use cli::Command;
use net_encode::BufSerialise;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::SmallRng;

use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::path::Path;

mod cli;
mod net_encode;

const RECEIVER_PORT: u16 = 4321;
const UDP_HEADER_SIZE: u16 = 8;
const IP4_HEADER_SIZE: u16 = 20;
const SAFE_IP4_PACKET_SIZE: u16 = 1280 - IP4_HEADER_SIZE - UDP_HEADER_SIZE;

fn main() {
    let cli::Cli {
        remote,
        command,
        unless,
        after,
    } = dbg!(cli::Cli::parse());

    let buf = Vec::with_capacity(1000);
    let mut com_enc = CommandEnc::new(buf);
    com_enc.encode_command(&command);

    let mut rng = SmallRng::from_os_rng();

    let sock = bind_socket(&mut rng);

    let packet = [8u8; SAFE_IP4_PACKET_SIZE as usize];
    sock.send_to(
        &packet,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, RECEIVER_PORT),
    )
    .unwrap();
}

pub struct CommandEnc {
    buf: Vec<u8>,
}

impl CommandEnc {
    pub fn new(buf: Vec<u8>) -> CommandEnc {
        CommandEnc { buf }
    }

    pub fn to_buf(self) -> Vec<u8> {
        self.buf
    }

    pub fn buf_slice(&self) -> &[u8] {
        &self.buf
    }

    fn read_file<P: AsRef<Path>>(&mut self, path: P) {
        // For now we will assume that the path exists
        let f = File::open(path).expect("Requested file does not exist");
        let mut reader = BufReader::new(f);
        reader.read_to_end(&mut self.buf).unwrap();
    }

    fn read_file_offset<P: AsRef<Path>>(&mut self, path: P, offset: u64) {
        // For now we will assume that the path exists and the offset is valid
        let f = File::open(path).expect("Requested file does not exist");
        let mut reader = BufReader::new(f);
        reader
            .seek_relative(offset as i64)
            .expect("Requested file is smaller than requested offset");
        reader.read_to_end(&mut self.buf).unwrap();
    }

    fn encode_command(&mut self, command: &Command) {
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
                self.buf.extend_from_slice(&id.to_le_bytes());
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
                self.buf.extend_from_slice(&id.to_le_bytes());
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

fn bind_socket(rng: &mut impl Rng) -> UdpSocket {
    loop {
        let port: u16 = rng.random_range(1024..=u16::MAX);
        match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)) {
            Ok(sock) => {
                eprintln!("Bound to: {}:{}", Ipv4Addr::UNSPECIFIED, port);
                break sock;
            }
            Err(_) => continue,
        }
    }
}
