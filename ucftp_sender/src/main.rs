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

// TODO:
// - maybe switch to big endian ints, to match raptorq and other net protocols
// - for regular sessions, what about using "epochs" to utilize shorter packet
//   seq numbers, with higher bits inferred (this allows packet disambiguiation
//   within 32 bit range, so enough for pretty much all reasonable net links)
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
    // packet size from cli includes all headers
    let packet_size = packet_size - IP4_HEADER_SIZE - UDP_HEADER_SIZE;

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
        warn!("not using FEC, because all data fits in one packet");
        fec = false;
    }

    let mut total_bytes_sent: usize;
    let send_start: Instant;
    if !fec {
        let mut packet_iter = PacketIter::new(
            &mut rng,
            protocol_message,
            crypto_ctx,
            encapped_key,
            packet_size,
        );
        info!("sending command with session {}", packet_iter.session_id());

        send_start = Instant::now();
        total_bytes_sent = 0;
        match max_speed {
            // Apply throttling
            Some(speed_kbps) => {
                // We enforce speed limit in intervals of THROTTLE_TIME_STEP_MS
                // KBPS * <ms_time_interval> = bytes/<ms_time_interval>
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
        send_start = Instant::now();
        debug!("sending FEC session init packet");
        send_retry(&sock, &init_packet_buf);
        total_bytes_sent = init_packet_buf.len();
        init_packet_buf.clear();
        debug!("sending FEC packets");
        match max_speed {
            // Apply throttling
            Some(speed_kbps) => {
                // We enforce speed limit in intervals of THROTTLE_TIME_STEP_MS
                // KBPS * <ms_time_interval> = bytes/<ms_time_interval>
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
    }
    let total_duration = Instant::now().duration_since(send_start);
    let secs = total_duration.as_secs_f32();
    let speed = total_bytes_sent as f32 / (secs * 1000.0);
    info!("average send speed: {speed:.2} kB/s");
    info!("command sent, shutting down");
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
