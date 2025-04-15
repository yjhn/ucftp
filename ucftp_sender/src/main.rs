use clap::Parser;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::SmallRng;

use std::cmp::min;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::time;
use std::time::Duration;

use message::UnlessAfter;
use message::serialise_message;
use serialise::BufSerialise;

mod cli;
mod message;
mod serialise;

const PROTOCOL_TIME_UNIX_EPOCH_OFFSET: u32 = 1735689600;
const RECEIVER_PORT: u16 = 4321;
const UDP_HEADER_SIZE: u16 = 8;
const IP4_HEADER_SIZE: u16 = 20;
const SAFE_IP4_PACKET_SIZE: u16 = 1280 - IP4_HEADER_SIZE - UDP_HEADER_SIZE;
const PROTOCOL_IDENTIFIER: &[u8; 6] = b"UCFTP\x01";
// TODO: FEC packets
pub enum PacketType {
    // FirstData = 0,
    RegularData = 1,
    LastData,
}

fn protocol_time() -> u32 {
    // SystemTime::now() gives UTC current time.
    // It is not monotonic, which is not ideal
    // Implementation from:
    // https://github.com/jedisct1/rust-coarsetime/blob/0.1.36/src/clock.rs#L84
    let unix_ts_now_sys = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .expect("The system clock is not properly set");

    let unix_ts_now = Duration::from(unix_ts_now_sys);

    (unix_ts_now.as_secs() - PROTOCOL_TIME_UNIX_EPOCH_OFFSET as u64) as u32
}

pub struct PacketIter<R: Rng> {
    session_id: u64,
    // actually, u48
    packet_sequence_number: u64,
    rng: R,
    protocol_message: Vec<u8>,
    protocol_message_used: usize,
    enc_ctx: EncryptionContext,
    extensions: SessionExtensions,
    packet_size: u16,
    packet_buffer: Vec<u8>,
}

pub struct EncryptionContext {}
// TODO: FEC as an extension?
pub struct SessionExtensions {}

impl<R: Rng> PacketIter<R> {
    pub fn new(
        mut rng: R,
        protocol_message: Vec<u8>,
        enc_ctx: EncryptionContext,
        extensions: SessionExtensions,
        packet_size: u16,
    ) -> Self {
        let session_id = rng.random();
        let packet_buffer = Vec::with_capacity(packet_size as usize);
        Self {
            session_id,
            packet_sequence_number: 0,
            rng,
            protocol_message,
            protocol_message_used: 0,
            enc_ctx,
            extensions,
            packet_size,
            packet_buffer,
        }
    }

    fn fill_packet(&mut self) {
        // Session ID
        self.session_id.serialise_to_buf(&mut self.packet_buffer);
        // Packet sequence number is a u48 stored in u64
        self.packet_buffer
            .extend_from_slice(&0u64.to_le_bytes()[..6]);
        self.packet_sequence_number += 1;
        // Length depends on body length
        let packet_overhead = self.packet_buffer.len() as u16 + 2 + 4 + 16;
        let body_len = min(
            self.protocol_message.len(),
            (SAFE_IP4_PACKET_SIZE - packet_overhead) as usize,
        );
        let len: u16 = body_len as u16 + packet_overhead;
        self.packet_buffer.extend_from_slice(&len.to_le_bytes());
        // Send time
        let t: u32 = protocol_time();
        self.packet_buffer.extend_from_slice(&t.to_le_bytes());
        // Body. TODO: encryption
        self.packet_buffer.extend_from_slice(
            &self.protocol_message
                [self.protocol_message_used..self.protocol_message_used + body_len],
        );
        self.protocol_message_used += body_len;
        // TODO: auth tag. For now it is a placeholder
        for _ in 0..16u8 {
            self.packet_buffer.push(0);
        }
    }

    pub fn next_packet(&mut self) -> &[u8] {
        if self.packet_sequence_number == 0 {
            // First packet
            // Protocol identifier
            self.packet_buffer.extend_from_slice(PROTOCOL_IDENTIFIER);
            // TODO: key exchange data
            // Number of extensions
            self.packet_buffer.push(0);
            self.fill_packet();
        } else {
            self.packet_buffer.push(PacketType::RegularData as u8);
            self.fill_packet();
        }
        // TODO: determine last packet
        // TODO(thesis): what if first packet is the last?

        // Sanity check
        assert!(self.packet_size as usize == self.packet_buffer.len());
        &self.packet_buffer
    }
}

fn main() {
    let cli::Cli {
        remote_ip,
        command,
        unless_session_id,
        unless_wait,
        after_session_ids,
        after_wait,
    } = dbg!(cli::Cli::parse());

    let buf = serialise_message(
        &command,
        UnlessAfter {
            unless_session_id,
            unless_wait,
            after_session_ids,
            after_wait,
        },
    );

    let mut rng = SmallRng::from_os_rng();

    let sock = bind_socket(&mut rng);

    let packet = [8u8; SAFE_IP4_PACKET_SIZE as usize];
    sock.send_to(&packet, SocketAddrV4::new(remote_ip, RECEIVER_PORT))
        .unwrap();
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
