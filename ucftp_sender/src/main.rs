use clap::Parser;
use cli::Cli;
use env_logger::{self, fmt::WriteStyle};
use hpke::Serializable;
use hpke::aead::AeadCtxS;
use log::{debug, error, info, trace, warn};
use rand::CryptoRng;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use raptorq;

use ucftp_shared::serialise::dump_le;
use ucftp_shared::*;

use std::cmp::min;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use std::time::Instant;

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
    regular_packet_data_size: u16,
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
            regular_packet_data_size: packet_size
                - 16 // auth tag
                - 4  // time
                - 1  // packet type
                - 6  // sequence number
                - 8, // session ID
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
        // dbg!(self.packet_size);
        // dbg!(packet_overhead);
        let body_len = min(
            self.protocol_message.len() - self.protocol_message_used,
            (self.packet_size - packet_overhead) as usize,
        );
        // let len: u16 = body_len as u16 + packet_overhead;
        // self.packet_buffer.extend_from_slice(&len.to_le_bytes());
        let aad_end = self.packet_buffer.len();
        // Send time. TODO(thesis): do we really need to encrypt the time?
        // If we do not encrypt it, we get no benefit. Time still must be verified
        // to be trustworthy
        let t: u32 = protocol_time();
        self.packet_buffer.extend_from_slice(&t.to_le_bytes());
        // Body. Encryption works in-place, so we first write plaintext data to
        // the buffer and then encrypt it
        self.packet_buffer.extend_from_slice(
            &self.protocol_message
                [self.protocol_message_used..self.protocol_message_used + body_len],
        );
        trace!(
            "encrypted {} bytes, AAD len {} bytes",
            self.packet_buffer.len() - aad_end,
            aad_end
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

    fn fill_packet_buf(&mut self, buf: &mut Vec<u8>, buf_start: usize) {
        // Session ID
        dump_le(buf, self.session_id);
        // Packet sequence number is a u48 stored in u64
        buf.extend_from_slice(&self.packet_sequence_number.to_le_bytes()[..6]);
        self.packet_sequence_number += 1;
        // Length depends on body length
        let packet_overhead = (buf.len() - buf_start) as u16 + 14 + 4 + 16;
        // dbg!(self.packet_size);
        // dbg!(packet_overhead);
        let body_len = min(
            self.protocol_message.len() - self.protocol_message_used,
            (self.packet_size - packet_overhead) as usize,
        );
        let aad_end = buf.len();
        let t: u32 = protocol_time();
        buf.extend_from_slice(&t.to_le_bytes());
        // Body. Encryption works in-place, so we first write plaintext data to
        // the buffer and then encrypt it
        buf.extend_from_slice(
            &self.protocol_message
                [self.protocol_message_used..self.protocol_message_used + body_len],
        );
        trace!(
            "encrypted {} bytes, AAD len {} bytes",
            buf.len() - aad_end,
            aad_end - buf_start
        );
        self.protocol_message_used += body_len;
        let (aad, data) = buf.split_at_mut(aad_end);
        let auth_tag = self
            .crypto_ctx
            .seal_in_place_detached(data, &aad[buf_start..])
            .unwrap();
        // Auth tag
        let data_end = buf.len();
        for _ in 0..16u8 {
            buf.push(0);
        }
        auth_tag.write_exact(&mut buf[data_end..]);
    }

    /// True = success, false = fail. Same as Some() and None for next_packet()
    /// buf does not have to be empty
    pub fn next_packet_buf(&mut self, buf: &mut Vec<u8>) -> bool {
        if self.protocol_message_used == self.protocol_message.len() {
            return false;
        }

        let start = buf.len();
        if self.packet_sequence_number == 0 {
            // First packet
            // Protocol identifier
            buf.extend_from_slice(PROTOCOL_IDENTIFIER);
            let start_idx = buf.len();
            for _ in 0..size_of::<EncappedKey>() {
                buf.push(0);
            }
            self.encapped_key.write_exact(&mut buf[start_idx..]);
            // Number of extensions
            buf.push(0);
            self.fill_packet_buf(buf, start);
        } else if buf.len() - self.protocol_message_used <= self.regular_packet_data_size as usize {
            buf.push(PacketType::LastData as u8);
            self.fill_packet_buf(buf, buf.len() - 1);
        } else {
            buf.push(PacketType::RegularData as u8);
            self.fill_packet_buf(buf, buf.len() - 1);
        }
        // TODO(thesis): what if first packet is also the last?

        true
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
        } else if self.protocol_message.len() - self.protocol_message_used
            <= self.regular_packet_data_size as usize
        {
            self.packet_buffer.clear();
            self.packet_buffer.push(PacketType::LastData as u8);
            self.fill_packet();
        } else {
            self.packet_buffer.clear();
            self.packet_buffer.push(PacketType::RegularData as u8);
            self.fill_packet();
        }
        // TODO(thesis): what if first packet is also the last?

        Some(&self.packet_buffer)
    }
}

// RaptorQ FEC usage:
// - collect all packets into an array
// - special case: 1 packet - no FEC needed
// - encode them with
fn main() {
    env_logger::builder()
        .format_timestamp(None)
        .format_target(false)
        .write_style(WriteStyle::Always)
        .init();
    let cli = Cli::parse();
    info!("starting up");
    debug!("args: {:?}", &cli);
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
        max_speed,
    } = cli;

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
    let receiver = SocketAddrV4::new(remote_ip, RECEIVER_PORT);
    let sock = bind_socket(&mut rng, receiver);

    let (sender_sk, sender_pk, receiver_pk) = get_keys(sender_keys_dir, receiver_pk_file);
    let (encapped_key, crypto_ctx) =
        init_sender_crypto(&mut rng, sender_sk, sender_pk, &receiver_pk);

    let use_fec = true;
    if !use_fec {
        let mut packet_iter = PacketIter::new(
            &mut rng,
            protocol_message,
            crypto_ctx,
            encapped_key,
            SessionExtensions {},
            packet_size,
        );
        info!("sending command with session {}", packet_iter.session_id);

        let send_start = Instant::now();
        let mut total_bytes_sent = 0;
        match max_speed {
            // Apply throttling
            Some(speed_kbps) => {
                // We enforce speed limit in intervals of THROTTLE_TIME_STEP_MS
                // KBPS * <ms_time_interval> = bytes/<ms_time_interval>
                // TODO: make time step inversely proportional to speed
                let throttle_time_step_ms = {
                    let t = 20_000 / speed_kbps;
                    if t == 0 { 1 } else { t }
                };
                debug!("using {}ms throttle time step", throttle_time_step_ms);
                let desired_bytes = speed_kbps * throttle_time_step_ms;
                let mut start = send_start;
                let mut actual_bytes = 0;
                while let Some(packet) = packet_iter.next_packet() {
                    if actual_bytes > desired_bytes {
                        let now = Instant::now();
                        let duration = (now - start).as_millis() as u64;
                        // Check if speed is greater than required
                        if duration < throttle_time_step_ms as u64 {
                            trace!(
                                "throttling, {}ms quota filled in {}ms",
                                throttle_time_step_ms, duration
                            );
                            // Sleep for the remainder of quota duration.
                            // For some reason the total speed is much higher if the
                            // duration is not multiplied by 2, even though I don't
                            // know why that's the case
                            thread::sleep(Duration::from_millis(
                                (throttle_time_step_ms as u64 - duration) * 2,
                            ));
                        }
                        trace!(
                            "actual quota duration: {}ms, len: {} bytes",
                            Instant::now().duration_since(start).as_millis(),
                            actual_bytes
                        );
                        start = now;
                        actual_bytes -= desired_bytes;
                    }
                    send_retry(&sock, packet);
                    total_bytes_sent += packet.len();
                    actual_bytes += packet.len() as u32;
                }
            }
            None => {
                while let Some(packet) = packet_iter.next_packet() {
                    send_retry(&sock, packet);
                    total_bytes_sent += packet.len();
                }
            }
        }
        let total_duration = Instant::now().duration_since(send_start);
        let secs = total_duration.as_secs_f32();
        let speed = total_bytes_sent as f32 / (secs * 1000.0);
        info!("average send speed: {speed:.2} kB/s");
        info!("command sent, shutting down");
    } else {
        let mut packet_iter = PacketIter::new(
            &mut rng,
            protocol_message,
            crypto_ctx,
            encapped_key,
            SessionExtensions {},
            packet_size
                - 4  // raptorq adds 4 bytes of overhead to every packet
                - 9, // FEC packets are 9 bytes larger than regular ones and must
                     // still fit into the required size, so regular packets must
                     // be 9 bytes shorter. TODO: is there a better way?
        );
        info!(
            "sending command with session {}, using FEC",
            packet_iter.session_id
        );
        let mut packets = Vec::with_capacity(
            packet_iter.protocol_message.len() + packet_iter.protocol_message.len() / 10,
        );
        let mut type_session = [0; 9];
        type_session[0] = PacketType::ErrorCorrection as u8;
        type_session[1..].copy_from_slice(&packet_iter.session_id.to_le_bytes());
        // Collect all packets
        // First packet is special - it is not included in FEC, because it
        // specifies FEC settings
        let first_packet = packet_iter.next_packet().unwrap();
        let send_start = Instant::now();
        // TODO: what about packet types? It should probably remain the first packet byte. Otherwise we need to be very careful to not make init packet detection
        // brittle (because 4 FEC bytes can be of any value), including UCFT
        // TODO: FEC packets need their own packet type, also session ID and sequence number
        send_retry(&sock, first_packet);
        let mut total_bytes_sent = first_packet.len();
        while packet_iter.next_packet_buf(&mut packets) {}
        debug!("total packets len before FEC: {} bytes", packets.len());
        // This is super slow in debug builds, but really fast in release
        let fec_encoder = raptorq::Encoder::with_defaults(&packets, packet_size);
        match max_speed {
            // Apply throttling
            Some(speed_kbps) => {
                // We enforce speed limit in intervals of THROTTLE_TIME_STEP_MS
                // KBPS * <ms_time_interval> = bytes/<ms_time_interval>
                // TODO: make time step inversely proportional to speed
                // TODO(thesis): non-init packets will not include time field
                // Reasoning:
                // - session init packet must have time to detect replays
                // - subsequent packets' decryption depends on the key from init
                // - there is a truly negligible probability of randomly getting
                //   the same keys for different sessions
                // - without having the key, time cannot be reliably checked anyway
                // - so if the replay attack happens:
                //   - init packet replay will be detected, because it has a timestamp
                //   - subsequent packets will be dropped if first one has old time
                //   - if init packet is not received, subsequent packets will
                //     be put in a session that will naturally time out without
                //     decrypting them
                //   - so there is no way to replay non-init packets without detection
                //     assumbing no accidentally duplicate keys
                //   - if session ID collision happens, it doesn't affect this
                //     property, because packets will fail decryption
                let throttle_time_step_ms = {
                    let t = 20_000 / speed_kbps;
                    if t == 0 { 1 } else { t }
                };
                debug!("using {}ms throttle time step", throttle_time_step_ms);
                let desired_bytes = speed_kbps * throttle_time_step_ms;
                let mut start = send_start;
                let mut actual_bytes = 0;
                // TODO: make overhead configurable
                for packet in fec_encoder
                    .get_encoded_packets(
                        (packet_iter.packet_sequence_number
                            + packet_iter.packet_sequence_number / 2)
                            as u32,
                    )
                    .into_iter()
                    .map(|p| {
                        // Serialize manually. Taken from:
                        // https://github.com/cberner/raptorq/blob/v2.0.0/src/base.rs#L85
                        let mut ser = Vec::with_capacity(13 + p.data().len());
                        ser.extend_from_slice(&type_session);
                        ser.extend_from_slice(&p.payload_id().serialize());
                        ser.extend_from_slice(p.data());
                        ser
                    })
                {
                    // while let Some(packet) = packet_iter.next_packet() {
                    if actual_bytes > desired_bytes {
                        let now = Instant::now();
                        let duration = (now - start).as_millis() as u64;
                        // Check if speed is greater than required
                        if duration < throttle_time_step_ms as u64 {
                            trace!(
                                "throttling, {}ms quota filled in {}ms",
                                throttle_time_step_ms, duration
                            );
                            // Sleep for the remainder of quota duration.
                            // For some reason the total speed is much higher if the
                            // duration is not multiplied by 2, even though I don't
                            // know why that's the case
                            thread::sleep(Duration::from_millis(
                                (throttle_time_step_ms as u64 - duration) * 2,
                            ));
                        }
                        trace!(
                            "actual quota duration: {}ms, len: {} bytes",
                            Instant::now().duration_since(start).as_millis(),
                            actual_bytes
                        );
                        start = now;
                        actual_bytes -= desired_bytes;
                    }
                    send_retry(&sock, &packet);
                    total_bytes_sent += packet.len();
                    actual_bytes += packet.len() as u32;
                }
            }
            None => {
                for packet in fec_encoder
                    .get_encoded_packets(
                        (packet_iter.packet_sequence_number
                            + packet_iter.packet_sequence_number / 2)
                            as u32,
                    )
                    .into_iter()
                    .map(|p| {
                        let mut ser = Vec::with_capacity(13 + p.data().len());
                        ser.extend_from_slice(&type_session);
                        ser.extend_from_slice(&p.payload_id().serialize());
                        ser.extend_from_slice(p.data());
                        ser
                    })
                {
                    // while let Some(packet) = packet_iter.next_packet() {
                    send_retry(&sock, &packet);
                    total_bytes_sent += packet.len();
                }
            }
        }
        let total_duration = Instant::now().duration_since(send_start);
        let secs = total_duration.as_secs_f32();
        let speed = total_bytes_sent as f32 / (secs * 1000.0);
        info!("average send speed: {speed:.2} kB/s");
        info!("command sent, shutting down");
    }
}

fn send_retry(socket: &UdpSocket, packet: &[u8]) {
    trace!("sending packet");
    loop {
        match socket.send(packet) {
            Ok(_) => {
                // trace!("ok");
                return;
            }
            Err(e) => {
                warn!("error sending packet: {e}, retrying in 1s");
                thread::sleep(Duration::from_secs(1));
                return;
            }
        }
    }
}

// Returns (sender_sk, sender_pk, receiver_pk)
fn get_keys(
    sender_keys_dir: Option<PathBuf>,
    receiver_pk_file: Option<PathBuf>,
) -> (PrivateKey, PublicKey, PublicKey) {
    let sender_keys_dir = sender_keys_dir.unwrap_or_else(|| PathBuf::from_str(".").unwrap());
    info!("reading sender keys from '{}'", sender_keys_dir.display());
    let (sender_sk, sender_pk) = read_sender_keys(sender_keys_dir);
    let receiver_key_file =
        receiver_pk_file.unwrap_or_else(|| PathBuf::from_str("./receiver_pk.pem").unwrap());
    info!(
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
    info!("reading private key from {}", dir.display());
    let sk = read_sk(&dir).unwrap();
    dir.pop();
    dir.push("sender_pk.pem");
    info!("reading sender public key from {}", dir.display());
    let pk = read_pk(&dir).unwrap();

    (sk, pk)
}

fn bind_socket(rng: &mut impl Rng, receiver: SocketAddrV4) -> UdpSocket {
    let socket = loop {
        let port: u16 = rng.random_range(1024..=u16::MAX);
        let socket = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        match UdpSocket::bind(socket) {
            Ok(sock) => {
                debug!("bound to: {}", socket);
                break sock;
            }
            Err(_) => continue,
        }
    };
    socket.connect(receiver).unwrap();
    debug!("receiver: {}", receiver);
    socket
}
