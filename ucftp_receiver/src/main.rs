mod cli;
mod executor;
mod message;
mod session;

use std::fs;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Instant;

use clap::Parser;
use cli::Cli;
use env_logger::{self, fmt::WriteStyle};
use executor::GlobalExecutor;
use log::{debug, error, info, trace, warn};
use message::CommandExecutor;
use session::EncryptedPacket;
use session::InProgressFecSession;
use session::InProgressSession;
use session::MIN_FIRST_PACKET_LEN;
use session::SessionStatus;
use session::UninitFecSession;
use session::UninitSession;
use socket2::{Domain, Socket, Type};
use ucftp_shared::serialise::u64_from_le_bytes;
use ucftp_shared::*;

// Equipment that allows frames larger than 9216 bytes is very rare
const MAX_PACKET_SIZE: u16 = 9216 - 18 - IP4_HEADER_SIZE - UDP_HEADER_SIZE;
const SUPPORTED_PACKET_SIZE: u16 = 1500;
const RECEIVE_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, RECEIVER_PORT);
const RECV_BUFFER_SIZE: usize = 100_000_000;

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

    let (receiver_sk, sender_pks) = get_keys(cli.receiver_sk_file, cli.sender_keys_dir);

    let sock = create_socket();

    let mut receiver = Receiver::new(sock, sender_pks.into_boxed_slice(), receiver_sk);

    receiver.receive_loop();
}

fn create_socket() -> UdpSocket {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).expect("Failed to create socket");
    // TODO(future): use non-blocking IO (sock.set_nonblocking(true)) to waste less
    // time waiting
    socket
        .bind(&RECEIVE_ADDR.into())
        .expect("Failed to bind to port 4321");
    // TODO(thesis): mention this and that it improves reliability with larger file
    // transfers, at least without FEC
    socket.set_recv_buffer_size(RECV_BUFFER_SIZE).unwrap();
    info!("listening on {}", RECEIVE_ADDR);
    socket.into()
}

// Returns (receiver_sk, Vec<sender_pk>)
fn get_keys(
    receiver_sk_file: Option<PathBuf>,
    sender_keys_dir: Option<PathBuf>,
) -> (PrivateKey, Vec<PublicKey>) {
    let receiver_sk_file =
        receiver_sk_file.unwrap_or_else(|| PathBuf::from_str("./receiver_sk.pem").unwrap());
    info!(
        "reading receiver private key from '{}'",
        receiver_sk_file.display()
    );
    let receiver_sk = read_sk(receiver_sk_file).unwrap();

    let sender_keys_dir = sender_keys_dir.unwrap_or_else(|| PathBuf::from_str("./").unwrap());
    info!(
        "reading sender public keys from '{}'",
        sender_keys_dir.display()
    );
    let paths = fs::read_dir(sender_keys_dir).unwrap();
    let mut sender_keys = Vec::with_capacity(4);
    for p in paths {
        let p = p.unwrap().path();
        let k = match read_pk(&p) {
            Ok(k) => k,
            Err(_) => continue,
        };
        sender_keys.push(k);
        debug!("read sender key from '{}'", p.display());
    }

    (receiver_sk, sender_keys)
}

struct Receiver {
    socket: UdpSocket,
    sender_pks: Box<[PublicKey]>,
    receiver_sk: PrivateKey,
    uninit_sessions: Vec<UninitSession>,
    in_progress_sessions: Vec<InProgressSession>,
    uninit_fec_sessions: Vec<UninitFecSession>,
    in_progress_fec_sessions: Vec<InProgressFecSession>,
    // packet_buf: [u8; MAX_PACKET_SIZE as usize],
    command_executor: GlobalExecutor,
}

impl Receiver {
    fn new(socket: UdpSocket, sender_pks: Box<[PublicKey]>, receiver_sk: PrivateKey) -> Self {
        Receiver {
            socket,
            sender_pks,
            receiver_sk,
            // packet_buf: [0; MAX_PACKET_SIZE as usize],
            uninit_sessions: Vec::new(),
            in_progress_sessions: Vec::new(),
            in_progress_fec_sessions: Vec::new(),
            uninit_fec_sessions: Vec::new(),
            command_executor: GlobalExecutor::new(),
        }
    }

    fn add_in_progress(&mut self, session: InProgressSession) {
        info!("tracking new in-progress session {}", session.session_id());
        self.in_progress_sessions.push(session);
    }

    fn add_uninit(&mut self, session: UninitSession) {
        info!("tracking new uninit session {}", session.session_id());
        self.uninit_sessions.push(session);
    }

    fn add_in_progress_fec(&mut self, session: InProgressFecSession) {
        info!(
            "tracking new in-progress FEC session {}",
            session.session_id()
        );
        self.in_progress_fec_sessions.push(session);
    }

    fn add_uninit_fec(&mut self, session: UninitFecSession) {
        info!("tracking new uninit FEC session {}", session.session_id());
        self.uninit_fec_sessions.push(session);
    }

    /// Returns a newly finished session if the packet finished one
    #[must_use]
    fn handle_packet(&mut self, mut packet: Vec<u8>) -> Option<CommandExecutor> {
        // Packet must belong to one of the known types
        let packet_type = match PacketType::try_from(packet[0]) {
            Ok(p) => p,
            Err(_) => {
                error!("unrecognized packet type");
                return None;
            }
        };
        match packet_type {
            PacketType::FirstData => {
                // TODO: init FEC packets
                // TODO(refactor): don't decrypt the packet,
                // hand it over immediately to the session, it will know
                // whether it is worth decrypting
                if packet.len() < MIN_FIRST_PACKET_LEN as usize {
                    error!("packet too short");
                    return None;
                }
                match packet[6] {
                    0 => self.handle_session_init_packet(&mut packet),
                    1 => self.handle_fec_session_init_packet(&mut packet),
                    _ => {
                        error!("unsupported extensions, extension count: {}", packet[6]);
                        None
                    }
                }
            }
            PacketType::RegularData | PacketType::LastData => {
                // TODO: should processing be different between regular and last?
                let packet = match EncryptedPacket::try_from_buf(&packet[1..], packet_type) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("failed to parse regular packet: {:?}", e);
                        return None;
                    }
                };
                let now = Instant::now();
                let mut i = 0;
                while i < self.uninit_sessions.len() {
                    let s = &mut self.uninit_sessions[i];
                    if s.progress_timeout_from(now) {
                        info!("timeout for session {}", s.session_id());
                        self.uninit_sessions.swap_remove(i);
                        // We swap-removed current elem from the list, so the
                        // index does not advance
                        continue;
                    }
                    if s.session_id() == packet.session_id() {
                        s.add_packet(packet);
                        return None;
                    }
                    i += 1;
                }
                i = 0;
                while i < self.in_progress_sessions.len() {
                    let s = &mut self.in_progress_sessions[i];
                    if s.progress_timeout_from(now) {
                        info!("timeout for session {}", s.session_id());
                        self.in_progress_sessions.swap_remove(i);
                        // We swap-removed current elem from the list, so the
                        // index does not advance
                        continue;
                    }
                    if s.session_id() == packet.session_id() {
                        match s.add_packet(packet, now) {
                            SessionStatus::Complete(command_executor) => {
                                self.in_progress_sessions.swap_remove(i);
                                return Some(command_executor);
                            }
                            _ => return None,
                        }
                    }
                    i += 1;
                }
                // This is a truly new session
                self.add_uninit(UninitSession::from_middle_packet(packet));
                None
            }
            PacketType::ErrorCorrection => {
                // TODO: add to session
                let session_id = u64_from_le_bytes(&packet[1..]);
                trace!(
                    "error correction packet for session {} received",
                    session_id
                );
                let packet = raptorq::EncodingPacket::deserialize(&packet[9..]);
                let now = Instant::now();
                let mut i = 0;
                while i < self.uninit_fec_sessions.len() {
                    let s = &mut self.uninit_fec_sessions[i];
                    if s.progress_timeout_from(now) {
                        info!("timeout for session {}", s.session_id());
                        self.uninit_fec_sessions.swap_remove(i);
                        // We swap-removed current elem from the list, so the
                        // index does not advance
                        continue;
                    }
                    if s.session_id() == session_id {
                        s.add_packet(packet, session_id);
                        return None;
                    }
                    i += 1;
                }
                i = 0;
                while i < self.in_progress_fec_sessions.len() {
                    let s = &mut self.in_progress_fec_sessions[i];
                    if s.progress_timeout_from(now) {
                        info!("timeout for session {}", s.session_id());
                        self.in_progress_fec_sessions.swap_remove(i);
                        // We swap-removed current elem from the list, so the
                        // index does not advance
                        continue;
                    }
                    if s.session_id() == session_id {
                        match s.add_packet(packet, session_id, now) {
                            SessionStatus::Complete(command_executor) => {
                                self.in_progress_fec_sessions.swap_remove(i);
                                return Some(command_executor);
                            }
                            _ => return None,
                        }
                    }
                    i += 1;
                }
                // This is a truly new session
                self.add_uninit_fec(UninitFecSession::from_packet(packet, session_id));
                None
            }
        }
    }

    fn handle_session_init_packet(&mut self, packet: &mut Vec<u8>) -> Option<CommandExecutor> {
        let mut new_session = match InProgressSession::try_from_init_packet_buf(
            packet,
            &self.sender_pks,
            &self.receiver_sk,
        ) {
            Ok(p) => {
                trace!("init data packet received for session {}", p.session_id());
                match p.session_status() {
                    SessionStatus::Complete(command_executor) => {
                        return Some(command_executor);
                    }
                    SessionStatus::Incomplete => p,
                    // Session is complete and corrupt, so we discard it
                    SessionStatus::Corrupt => return None,
                }
            }
            Err(e) => {
                error!("failed to parse init packet: {:?}", e);
                return None;
            }
        };
        let now = Instant::now();
        let mut i = 0;
        // Try merging with uninit session having same session ID
        // TODO: here we check only uninit sessions. We should handle
        // duplicate first packets gracefully, not by starting a new session
        // for each, which will not work well
        while i < self.uninit_sessions.len() {
            let s = &self.uninit_sessions[i];
            // TODO(thesis): clearly specify that protocol time should only
            // be used to prevent replay attacks. Regular timing facilities
            // should be used for session timeouts

            // If this session happens to be the matching one, by removing
            // it we are much more likely to loop over all remaining ones
            // TODO: we should only check timeouts occasioanlly
            // (like every 5s), not on receive of every packet
            if s.progress_timeout_from(now) {
                info!("timeout for session {}", s.session_id());
                self.uninit_sessions.swap_remove(i);
                // We swap-removed current elem from the list, so the
                // index does not advance
                continue;
            }
            if s.session_id() == new_session.session_id() {
                let s = self.uninit_sessions.swap_remove(i);
                // We break here, but we should check timeouts of
                // the remaining sessions somewhere
                match new_session.merge(s, now) {
                    SessionStatus::Complete(command_executor) => {
                        return Some(command_executor);
                    }
                    SessionStatus::Incomplete => break,
                    // Session is complete and corrupt, so we discard it
                    SessionStatus::Corrupt => return None,
                }
            }
            i += 1;
        }
        // This is a truly new session
        self.add_in_progress(new_session);
        None
    }

    pub fn receive_loop(&mut self) {
        loop {
            // TODO: do not block here
            // TODO(future): use MaybeUninit?
            let mut packet = vec![0; SUPPORTED_PACKET_SIZE as usize];
            let (packet_len, addr) = self.socket.recv_from(&mut packet).unwrap();
            packet.truncate(packet_len);
            trace!("packet from {}", addr);

            // Packet processing steps:
            // 1. determine type:
            //    - first
            //    - regular
            // 2. parse:
            //    - if error, discard and log reason
            // 3. find session with matching session id
            //    - check if timeout occured
            // 4. hand over packet to that session
            if let Some(exec) = self.handle_packet(packet) {
                // TODO: add debug print impl that ignores file contents
                trace!("received command: {:?}", &exec);
                self.command_executor.add_pending(exec);
            }

            self.handle_completed_sessions();
        }
    }

    fn handle_completed_sessions(&mut self) {
        self.command_executor.work();
    }

    fn handle_fec_session_init_packet(&mut self, packet: &mut [u8]) -> Option<CommandExecutor> {
        let mut new_session = match InProgressFecSession::try_from_init_packet_buf(
            packet,
            &self.sender_pks,
            &self.receiver_sk,
        ) {
            Ok(mut p) => {
                trace!(
                    "init data packet received for FEC session {}",
                    p.session_id()
                );
                match p.session_status() {
                    SessionStatus::Complete(command_executor) => {
                        return Some(command_executor);
                    }
                    SessionStatus::Incomplete => p,
                    // Session is complete and corrupt, so we discard it
                    SessionStatus::Corrupt => return None,
                }
            }
            Err(e) => {
                error!("failed to parse FEC init packet: {:?}", e);
                return None;
            }
        };
        let now = Instant::now();
        let mut i = 0;
        // Try merging with uninit session having same session ID
        // TODO: here we check only uninit sessions. We should handle
        // duplicate first packets gracefully, not by starting a new session
        // for each, which will not work well
        while i < self.uninit_fec_sessions.len() {
            let s = &self.uninit_fec_sessions[i];
            // TODO(thesis): clearly specify that protocol time should only
            // be used to prevent replay attacks. Regular timing facilities
            // should be used for session timeouts

            // If this session happens to be the matching one, by removing
            // it we are much more likely to loop over all remaining ones
            // TODO: we should only check timeouts occasioanlly
            // (like every 5s), not on receive of every packet
            if s.progress_timeout_from(now) {
                info!("timeout for session {}", s.session_id());
                self.uninit_fec_sessions.swap_remove(i);
                // We swap-removed current elem from the list, so the
                // index does not advance
                continue;
            }
            if s.session_id() == new_session.session_id() {
                let s = self.uninit_fec_sessions.swap_remove(i);
                // We break here, but we should check timeouts of
                // the remaining sessions somewhere
                match new_session.merge(s, now) {
                    SessionStatus::Complete(command_executor) => {
                        return Some(command_executor);
                    }
                    SessionStatus::Incomplete => break,
                    // Session is complete and corrupt, so we discard it
                    SessionStatus::Corrupt => return None,
                }
            }
            i += 1;
        }
        // This is a truly new session
        self.add_in_progress_fec(new_session);
        None
    }
}
