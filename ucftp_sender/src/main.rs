use crate::packet::PacketIter;
use clap::Parser;
use cli::Cli;
use env_logger::{self, fmt::WriteStyle};
use log::{debug, info, trace, warn};
use packet::FecPacketIter;
use rand::SeedableRng;
use rand::rngs::StdRng;

use ucftp_shared::*;

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
mod packet;

// RaptorQ FEC usage:
// - collect all packets into an array
// - special case: 1 packet - no FEC needed
// - encode them with
fn main() {
    env_logger::builder()
        .format_timestamp(None)
        .format_target(false)
        .write_style(WriteStyle::Always)
        .filter_level(log::LevelFilter::max())
        .parse_default_env()
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
        mut fec,
        fec_overhead_percent,
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

    let receiver = SocketAddrV4::new(remote_ip, RECEIVER_PORT);
    let sock = bind_socket(receiver);

    let (sender_sk, sender_pk, receiver_pk) = get_keys(sender_keys_dir, receiver_pk_file);
    let mut rng = StdRng::from_os_rng();
    let (encapped_key, crypto_ctx) =
        init_sender_crypto(&mut rng, sender_sk, sender_pk, &receiver_pk);

    // Without any extensions
    let max_first_packet_data_size = packet_size - MIN_FIRST_PACKET_OVERHEAD;
    if max_first_packet_data_size as usize >= protocol_message.len() {
        // TODO(thesis): note this caveat
        warn!("not using FEC, because all data fits in one packet");
        fec = false;
    }
    // TODO(thesis): what to do if a session consisting of one packet gets duplicated?
    // We should somehow prevent double execution. Maybe look at previously executed
    // commands and do not execute unless a certain amount of time passed?
    // This also might be the way to deal with packets received for timed out sessions

    if !fec {
        let mut packet_iter = PacketIter::new(
            &mut rng,
            protocol_message,
            crypto_ctx,
            encapped_key,
            packet_size,
        );
        info!("sending command with session {}", packet_iter.session_id());

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
        let (mut packet_iter, mut init_packet_buf) = FecPacketIter::new(
            &mut rng,
            protocol_message,
            crypto_ctx,
            encapped_key,
            packet_size,
            fec_overhead_percent,
        );
        info!(
            "sending command with session {}, using FEC",
            packet_iter.session_id()
        );
        // TODO(thesis): First packet is special - it is not included in FEC, because it
        // specifies FEC settings
        let send_start = Instant::now();
        debug!("sending FEC session init packet");
        send_retry(&sock, &init_packet_buf);
        let mut total_bytes_sent = init_packet_buf.len();
        init_packet_buf.clear();
        debug!("sending FEC packets");
        match max_speed {
            // Apply throttling
            Some(speed_kbps) => {
                // We enforce speed limit in intervals of THROTTLE_TIME_STEP_MS
                // KBPS * <ms_time_interval> = bytes/<ms_time_interval>
                // TODO(thesis): maybe note that time step should be inversely proportional to speed
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
                while packet_iter.next_packet_buf(&mut init_packet_buf) {
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
                    send_retry(&sock, &init_packet_buf);
                    total_bytes_sent += init_packet_buf.len();
                    actual_bytes += init_packet_buf.len() as u32;
                    init_packet_buf.clear();
                }
            }
            None => {
                while packet_iter.next_packet_buf(&mut init_packet_buf) {
                    send_retry(&sock, &init_packet_buf);
                    total_bytes_sent += init_packet_buf.len();
                    init_packet_buf.clear();
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
                return;
            }
            Err(e) => {
                warn!("error sending packet: {e}, retrying in 1s");
                thread::sleep(Duration::from_secs(1));
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
    info!("reading private key from '{}'", dir.display());
    let sk = read_sk(&dir).unwrap();
    dir.pop();
    dir.push("sender_pk.pem");
    info!("reading sender public key from '{}'", dir.display());
    let pk = read_pk(&dir).unwrap();

    (sk, pk)
}

fn bind_socket(receiver: SocketAddrV4) -> UdpSocket {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let socket = UdpSocket::bind(addr).unwrap();
    debug!("bound to: {}", socket.local_addr().unwrap());

    socket.connect(receiver).unwrap();
    debug!("receiver: {}", receiver);
    socket
}
