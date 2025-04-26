use clap::Parser;
use hpke::Serializable;
use hpke::aead::AeadCtxS;
use rand::CryptoRng;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;

use ucftp_shared::serialise::dump_le;
use ucftp_shared::*;

use std::cmp::min;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::str::FromStr;

use message::UnlessAfter;
use message::serialise_message;

mod cli;
mod message;

pub struct PacketIter {
    session_id: u64,
    // actually, u48
    packet_sequence_number: u64,
    protocol_message: Vec<u8>,
    protocol_message_used: usize,
    crypto_ctx: AeadCtxS<ChosenAead, ChosenKdf, ChosenKem>,
    encapped_key: EncappedKey,
    extensions: SessionExtensions,
    packet_size: u16,
    packet_buffer: Vec<u8>,
}

impl PacketIter {
    pub fn new(
        rng: &mut impl CryptoRng,
        protocol_message: Vec<u8>,
        crypto_ctx: AeadCtxS<ChosenAead, ChosenKdf, ChosenKem>,
        encapped_key: EncappedKey,
        extensions: SessionExtensions,
        packet_size: u16,
    ) -> Self {
        let session_id = rng.random();
        let packet_buffer = Vec::with_capacity(packet_size as usize);
        Self {
            session_id,
            packet_sequence_number: 0,
            protocol_message,
            protocol_message_used: 0,
            crypto_ctx,
            encapped_key,
            extensions,
            packet_size,
            packet_buffer,
        }
    }

    // TODO(thesis): include total session plaintext length as the first session field
    fn fill_packet(&mut self) {
        // Session ID
        dump_le(&mut self.packet_buffer, self.session_id);
        // Packet sequence number is a u48 stored in u64
        self.packet_buffer
            .extend_from_slice(&self.packet_sequence_number.to_le_bytes()[..6]);
        self.packet_sequence_number += 1;
        // Length depends on body length
        let packet_overhead = self.packet_buffer.len() as u16 + 4 + 16;
        let body_len = min(
            self.protocol_message.len() - self.protocol_message_used,
            (self.packet_size - packet_overhead) as usize,
        );
        // let len: u16 = body_len as u16 + packet_overhead;
        // self.packet_buffer.extend_from_slice(&len.to_le_bytes());
        let aad_end = self.packet_buffer.len();
        // Send time. TODO(thesis): do we really need to encrypt the time?
        let t: u32 = protocol_time();
        self.packet_buffer.extend_from_slice(&t.to_le_bytes());
        // Body. Encryption works in-place, so we first write plaintext data to
        // the buffer and then encrypt it
        self.packet_buffer.extend_from_slice(
            &self.protocol_message
                [self.protocol_message_used..self.protocol_message_used + body_len],
        );
        self.protocol_message_used += body_len;
        let (aad, data) = self.packet_buffer.split_at_mut(aad_end);
        let auth_tag = self.crypto_ctx.seal_in_place_detached(data, aad).unwrap();
        // Auth tag
        let data_end = self.packet_buffer.len();
        for _ in 0..16u8 {
            self.packet_buffer.push(0);
        }
        auth_tag.write_exact(&mut self.packet_buffer[data_end..]);
    }

    pub fn next_packet(&mut self) -> Option<&[u8]> {
        if self.protocol_message_used == self.protocol_message.len() {
            return None;
        }

        if self.packet_sequence_number == 0 {
            // First packet
            // Protocol identifier
            self.packet_buffer.extend_from_slice(PROTOCOL_IDENTIFIER);
            let start_idx = self.packet_buffer.len();
            for _ in 0..size_of::<EncappedKey>() {
                self.packet_buffer.push(0);
            }
            self.encapped_key
                .write_exact(&mut self.packet_buffer[start_idx..]);
            // Number of extensions
            self.packet_buffer.push(0);
            self.fill_packet();
        } else {
            self.packet_buffer.push(PacketType::RegularData as u8);
            self.fill_packet();
        }
        // TODO: determine last packet
        // TODO(thesis): what if first packet is the last?

        Some(&self.packet_buffer)
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
        packet_size,
        sender_keys_dir,
        receiver_pk_file,
    } = dbg!(cli::Cli::parse());

    let protocol_message = serialise_message(
        &command,
        UnlessAfter {
            unless_session_id,
            unless_wait,
            after_session_ids,
            after_wait,
        },
    );

    let mut rng = StdRng::from_os_rng();
    let sock = bind_socket(&mut rng);

    let (sender_sk, sender_pk, receiver_pk) = get_keys(sender_keys_dir, receiver_pk_file);
    let (encapped_key, crypto_ctx) =
        init_sender_crypto(&mut rng, sender_sk, sender_pk, &receiver_pk);
    let mut packet_iter = PacketIter::new(
        &mut rng,
        protocol_message,
        crypto_ctx,
        encapped_key,
        SessionExtensions {},
        packet_size,
    );

    while let Some(packet) = packet_iter.next_packet() {
        sock.send_to(packet, SocketAddrV4::new(remote_ip, RECEIVER_PORT))
            .unwrap();
    }
}

// Returns (sender_sk, sender_pk, receiver_pk)
fn get_keys(
    sender_keys_dir: Option<PathBuf>,
    receiver_pk_file: Option<PathBuf>,
) -> (PrivateKey, PublicKey, PublicKey) {
    let sender_keys_dir = sender_keys_dir.unwrap_or_else(|| PathBuf::from_str(".").unwrap());
    eprintln!("reading sender keys from '{}'", sender_keys_dir.display());
    let (sender_sk, sender_pk) = read_sender_keys(sender_keys_dir);
    let receiver_key_file =
        receiver_pk_file.unwrap_or_else(|| PathBuf::from_str("./receiver_pk.pem").unwrap());
    eprintln!(
        "reading receiver public key from '{}'",
        receiver_key_file.display()
    );
    let receiver_pk = read_pk(receiver_key_file).unwrap();

    (sender_sk, sender_pk, receiver_pk)
}

// Keys are named sender_sk.pem and sender_pk.pem
// We parse PEM in the most primitive way possible
// Relevant structure of PEM for X25519:
// - public key:
//   - header: 12 bytes
//   - key: 32 bytes
// - private key:
//   - header: 16 bytes
//   - key: 32 bytes
// Last 32 bytes are the keys: https://stackoverflow.com/a/58209771
fn read_sender_keys(mut dir: PathBuf) -> (PrivateKey, PublicKey) {
    dir.push("sender_sk.pem");
    let sk = read_sk(&dir).unwrap();
    dir.pop();
    dir.push("sender_pk.pem");
    let pk = read_pk(&dir).unwrap();

    (sk, pk)
}

fn bind_socket(rng: &mut impl Rng) -> UdpSocket {
    loop {
        let port: u16 = rng.random_range(1024..=u16::MAX);
        let socket = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        match UdpSocket::bind(socket) {
            Ok(sock) => {
                eprintln!("bound to: {}", socket);
                break sock;
            }
            Err(_) => continue,
        }
    }
}
