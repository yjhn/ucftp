use base64::engine::{Engine, general_purpose::STANDARD as BASE64_STANDARD};
use clap::Parser;
use hpke::Deserializable;
use hpke::OpModeS;
use hpke::Serializable;
use hpke::aead::AeadCtxS;
use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use rand::CryptoRng;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;

use core::panic;
use std::cmp::min;
use std::fs;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::str::FromStr;
use std::time;

use message::UnlessAfter;
use message::serialise_message;
use serialise::BufSerialise;

mod cli;
mod message;
mod serialise;

type ChosenKem = X25519HkdfSha256;
type PrivateKey = <ChosenKem as hpke::Kem>::PrivateKey;
type PublicKey = <ChosenKem as hpke::Kem>::PublicKey;
type EncappedKey = <ChosenKem as hpke::Kem>::EncappedKey;
type ChosenAead = AesGcm128;
type ChosenKdf = HkdfSha256;

const PROTOCOL_TIME_UNIX_EPOCH_OFFSET: u32 = 1735689600;
const RECEIVER_PORT: u16 = 4321;
const PROTOCOL_IDENTIFIER: &[u8; 6] = b"UCFTP\x01";
const PROTOCOL_INFO: &[u8] = b"UCFTP";

// TODO(thesis): mention these sizes
const _: () = if size_of::<EncappedKey>() != 32 {
    panic!()
};

const _: () = if size_of::<hpke::aead::AeadTag<AesGcm128>>() != 16 {
    panic!()
};

// TODO: FEC packets
pub enum PacketType {
    // FirstData = 0, - first packet is already indicated by protocol identifier
    RegularData = 1,
    LastData,
}

fn protocol_time() -> u32 {
    // SystemTime::now() gives UTC current time.
    // It is not monotonic, which is not ideal
    // Implementation from:
    // https://github.com/jedisct1/rust-coarsetime/blob/0.1.36/src/clock.rs#L84
    let unix_ts_now = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .expect("The system clock is not properly set");

    (unix_ts_now.as_secs() - PROTOCOL_TIME_UNIX_EPOCH_OFFSET as u64) as u32
}

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

// TODO: FEC as an extension?
pub struct SessionExtensions {}

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
            (self.packet_size - packet_overhead) as usize,
        );
        let len: u16 = body_len as u16 + packet_overhead;
        self.packet_buffer.extend_from_slice(&len.to_le_bytes());
        let aad_end = self.packet_buffer.len();
        // Send time. TODO(thesis): do we really need to encrypt the time?
        let t: u32 = protocol_time();
        self.packet_buffer.extend_from_slice(&t.to_le_bytes());
        // Body
        self.packet_buffer.extend_from_slice(
            &self.protocol_message
                [self.protocol_message_used..self.protocol_message_used + body_len],
        );
        let (aad, data) = self.packet_buffer.split_at_mut(aad_end);
        let auth_tag = self.crypto_ctx.seal_in_place_detached(data, aad).unwrap();
        self.protocol_message_used += body_len;
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
            // TODO: key exchange data
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
        init_sender_crypto(&mut rng, sender_sk, sender_pk, receiver_pk);
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
    let receiver_pk = parse_pk(&fs::read_to_string(receiver_key_file).unwrap());

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
    let sk = parse_sk(&fs::read_to_string(&dir).unwrap());
    dir.pop();
    dir.push("sender_pk.pem");
    let pk = parse_pk(&fs::read_to_string(&dir).unwrap());

    (sk, pk)
}

fn parse_sk(pem: &str) -> PrivateKey {
    let mut buf = [0; 48];
    decode_pem_line(pem, &mut buf);
    PrivateKey::from_bytes(&buf[16..]).unwrap()
}

fn parse_pk(pem: &str) -> PublicKey {
    let mut buf = [0; 44];
    decode_pem_line(pem, &mut buf);
    PublicKey::from_bytes(&buf[12..]).unwrap()
}

fn decode_pem_line(pem: &str, buf: &mut [u8]) {
    let mut lines = pem.lines();
    lines.next();
    let key_base64 = lines.next().unwrap();
    BASE64_STANDARD.decode_slice(key_base64, buf).unwrap();
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

fn init_sender_crypto(
    rng: &mut impl CryptoRng,
    sender_sk: PrivateKey,
    sender_pk: PublicKey,
    receiver_pk: PublicKey,
) -> (EncappedKey, AeadCtxS<ChosenAead, ChosenKdf, ChosenKem>) {
    let opmode = OpModeS::Auth((sender_sk, sender_pk));
    hpke::setup_sender(&opmode, &receiver_pk, PROTOCOL_INFO, rng).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::{PrivateKey, PublicKey, parse_pk, parse_sk};
    use hpke::{Deserializable, Serializable};

    #[test]
    fn test_pem_sk_decode() {
        let pem = "\
            -----BEGIN PRIVATE KEY-----\n\
            MC4CAQAwBQYDK2VuBCIEIHAKHLUz5njU6wgTxEX8vpKXr4bIBleXWUGhKfPhN15B\n\
            -----END PRIVATE KEY-----";
        let sk = parse_sk(pem);
        let expected = PrivateKey::from_bytes(&[
            0x70, 0x0a, 0x1c, 0xb5, 0x33, 0xe6, 0x78, 0xd4, 0xeb, 0x08, 0x13, 0xc4, 0x45, 0xfc,
            0xbe, 0x92, 0x97, 0xaf, 0x86, 0xc8, 0x06, 0x57, 0x97, 0x59, 0x41, 0xa1, 0x29, 0xf3,
            0xe1, 0x37, 0x5e, 0x41,
        ])
        .unwrap();
        assert_eq!(expected.to_bytes(), sk.to_bytes());
    }

    #[test]
    fn test_pem_pk_decode() {
        let pem = "\
            -----BEGIN PUBLIC KEY-----\n\
            MCowBQYDK2VuAyEA/LYkVYQTh6+IM46ZEpdrf79Mgtr8mL1XZG8/niWghC8=\n\
            -----END PUBLIC KEY-----";
        let pk = parse_pk(pem);
        let expected = PublicKey::from_bytes(&[
            0xfc, 0xb6, 0x24, 0x55, 0x84, 0x13, 0x87, 0xaf, 0x88, 0x33, 0x8e, 0x99, 0x12, 0x97,
            0x6b, 0x7f, 0xbf, 0x4c, 0x82, 0xda, 0xfc, 0x98, 0xbd, 0x57, 0x64, 0x6f, 0x3f, 0x9e,
            0x25, 0xa0, 0x84, 0x2f,
        ])
        .unwrap();
        assert_eq!(expected.to_bytes(), pk.to_bytes());
    }
}
