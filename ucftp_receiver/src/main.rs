use std::mem;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;

use hpke::Deserializable;
use hpke::HpkeError;
use hpke::aead::AeadCtxR;
use hpke::aead::AeadTag;
use hpke::aead::AesGcm128;
use ucftp_shared::serialise::*;
use ucftp_shared::*;

// Equipment that allows frames larger than 9216 bytes is very rare
const MAX_PACKET_SIZE: u16 = 9216 - 18 - IP4_HEADER_SIZE - UDP_HEADER_SIZE;
const RECEIVE_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, RECEIVER_PORT);
const MIN_FIRST_PACKET_LEN: u16 = 6 // protocol ID
    + 32  // encapped key
    + 1   // number of extensions
    + 8   // session ID
    + 6   // sequence number
    + 4   // send time
    + 1   // there must be at least 1 byte of actual data
    + 16; // auth tag
const MIN_PACKET_LEN: u16 = 1 // packet type
    + 8   // session ID
    + 6   // sequence number
    + 4   // send time
    + 1   // data
    + 16; // auth tag

// Packet timeout = 4000 seconds
const MAX_ALLOWED_ABS_TIME_DIFF: u32 = 4000;

type CryptoCtx = AeadCtxR<ChosenAead, ChosenKdf, ChosenKem>;

fn packet_timeout(t: u32) -> bool {
    let time = protocol_time();
    if t > time {
        false
    } else {
        time - t > MAX_ALLOWED_ABS_TIME_DIFF
    }
}

// Architecture:
// - main loop listens on net interface
// - when a packet arrives:
//   - if it starts a new session, start a new session
//   - otherwise, try to decode the packet in all sessions in order from most to least likely
fn main() {
    let sock = UdpSocket::bind(RECEIVE_ADDR).expect("Failed to bind to port 4321");
    eprintln!("Listening on {}:{}", Ipv4Addr::UNSPECIFIED, RECEIVER_PORT);

    let mut packet_buf = [0; MAX_PACKET_SIZE as usize];
    // Establish a new session
    let mut session = loop {
        // recv_from receives a single packet
        let (len, addr) = sock.recv_from(&mut packet_buf).unwrap();
        // Sessions are not tied to IP addresses, just to their session IDs
        // For now we assume a single incoming session
        // Collect packets until we get the first packet
        // match Session::try_new(&packet_buf[..len]) {
        //     Ok(s) => break s,
        //     Err(e) => eprintln!("received packet error: {:?}", e),
        // }
    };
    // Receive all session packets

    loop {
        let (len, addr) = sock.recv_from(&mut packet_buf).unwrap();
    }
}

enum Command {}

// Packet with its header parsed, but body still encrypted
// Only non-first packet will ever be put in this state
struct EncryptedPacket {
    packet_type: PacketType,
    session_id: u64,
    sequence_number: u64,
    encrypted_data: Vec<u8>,
    auth_tag: AeadTag<AesGcm128>,
}

impl EncryptedPacket {
    fn try_from_buf(packet: &[u8], p_type: PacketType) -> Result<Self, PacketError> {
        debug_assert_ne!(p_type, PacketType::FirstData);
        debug_assert!(packet.len() >= MIN_PACKET_LEN as usize);
        let mut packet_used = 0;

        // Session ID
        let session_id = u64_from_le_bytes(&packet[packet_used..]);
        packet_used += 8;

        // Sequence number
        let sequence_number = seq_deser(&packet[packet_used..]);
        packet_used += 6;

        let buf_tag_start = packet.len() - 16;
        let (_aad, data_tag) = packet.split_at(packet_used);
        let auth_tag = AeadTag::from_bytes(&data_tag[buf_tag_start..]).unwrap();

        // Allocate storage for the protocol message
        let encrypted_data = Vec::from(&packet[packet_used..buf_tag_start]);

        Ok(EncryptedPacket {
            sequence_number,
            auth_tag,
            packet_type: p_type,
            encrypted_data,
            session_id,
        })
    }

    // This will corrupt the packet's buffer, so the packet will become useless
    // either way
    fn try_decrypt(
        mut self,
        crypto_ctx: &mut CryptoCtx,
        buf: &mut Vec<u8>,
    ) -> Result<u32, PacketError> {
        // Recreate AAD, structure:
        // - packet type
        // - session ID
        // - sequence number
        // use buf as scratch space
        buf.push(self.packet_type as u8);
        dump_le(buf, self.session_id);
        // Packet sequence number is a u48 stored in u64
        buf.extend_from_slice(&self.sequence_number.to_le_bytes()[..6]);

        match crypto_ctx.open_in_place_detached(
            &mut self.encrypted_data,
            &buf[buf.len() - 15..],
            &self.auth_tag,
        ) {
            Ok(_) => {
                // Clean up AAD
                buf.truncate(buf.len() - 15);
                // Caller must check for timeout
                let time = u32_from_le_bytes(&self.encrypted_data);
                buf.extend_from_slice(&self.encrypted_data[4..]);
                Ok(time)
            }
            Err(e) => {
                // Clean up AAD
                buf.truncate(buf.len() - 15);
                Err(PacketError::CryptoErr(e))
            }
        }
    }
}

struct FirstPacket {
    session_id: u64,
    session_extensions: SessionExtensions,
    sender_pk: PublicKey,
    sequence_number: u64,
    send_time: u32,
    decrypted_data: Vec<u8>,
    crypto_ctx: CryptoCtx,
}

impl FirstPacket {
    fn session_id(&self) -> u64 {
        self.session_id
    }

    // Try decoding and decrypting the first session packet. May overwrite
    // encrypted data, so buf must not be read from after calling this
    fn try_from_buf(
        mut packet: &mut [u8],
        sender_pks: &[PublicKey],
        receiver_sk: &PrivateKey,
    ) -> Result<Self, PacketError> {
        // Failure modes:
        // - header incorrect
        // - failed to decrypt encapsulated key
        // - failed to decrypt data
        // - data corrupt:
        //   - unknown message type
        //   - incorrect length
        // misc corruption (e.g. length incorrect)
        if packet.len() < MIN_FIRST_PACKET_LEN as usize {
            return Err(PacketError::Incomplete);
        }

        // Check header
        if &packet[..6] != PROTOCOL_IDENTIFIER {
            return Err(PacketError::WrongPacketType);
        }
        let mut packet_used = 6;
        // Encapsulated key
        // Try decapsulation using every known sender key
        // TODO: is there a better method?
        // This will never fail, as we are using x25519_dalek, which
        // has infallible key deserialisation
        let encapped_key = EncappedKey::from_bytes(&packet[packet_used..packet_used + 32]).unwrap();
        let (mut crypto_ctx, sender_pk) = match sender_pks.iter().cloned().find_map(|pk| {
            try_decapsulate_key(pk.clone(), receiver_sk, &encapped_key).map(|c| (c, pk))
        }) {
            Some(crypto_ctx) => crypto_ctx,
            None => return Err(PacketError::CryptoErr(HpkeError::DecapError)),
        };
        packet_used += 32;

        // Extensions. We don't support any
        if packet[packet_used] != 0 {
            return Err(PacketError::UnknownExtensions);
        }
        packet_used += 1;

        // Session ID
        let session_id = u64_from_le_bytes(&packet[packet_used..]);
        packet_used += 8;

        // Sequence number
        let sequence_number = seq_deser(&packet[packet_used..]);
        packet_used += 6;

        // Decrypt data
        // If decryption is unsuccessful, this may corrupt the ciphertext.
        // But since this is the first packet and the key has been
        // successfully decapped, this packet will be discarded if we fail
        // decryption anyway, so this doesn't matter
        let buf_tag_start = packet.len() - 16;
        let (aad, data_tag) = packet.split_at_mut(packet_used);
        // let (data, tag_bytes) = buf.split_at_mut(buf_tag_start);
        let auth_tag = AeadTag::from_bytes(&data_tag[buf_tag_start..]).unwrap();
        match crypto_ctx.open_in_place_detached(&mut data_tag[..buf_tag_start], aad, &auth_tag) {
            Ok(_) => (),
            Err(e) => return Err(PacketError::CryptoErr(e)),
        }

        let send_time = u32_from_le_bytes(&packet[packet_used..]);
        packet_used += 4;
        if packet_timeout(send_time) {
            return Err(PacketError::TooOld);
        }

        // Allocate storage for the protocol message
        let decrypted_data = Vec::from(&packet[packet_used..buf_tag_start]);

        Ok(FirstPacket {
            sender_pk,
            session_id,
            session_extensions: SessionExtensions::empty(),
            sequence_number,
            decrypted_data,
            send_time,
            crypto_ctx,
        })
    }
}

struct UninitSession {
    session_id: u64,
    // No packets can be decrypted without the first packet
    packet_buf: Vec<EncryptedPacket>,
    // Packet send time is encrypted. Even if it was not encrypted, we
    // could not trust it, because we can't verify its correctness until
    // we get the first packet. So the timeout logic in this case works
    // as follows: first session packet must arrive within 30 seconds of the
    // first received packet. Otherwise this session is discarded
    init_time: u32,
}

impl UninitSession {
    fn from_middle_packet(packet: EncryptedPacket) -> Self {
        UninitSession {
            session_id: packet.session_id,
            packet_buf: vec![packet],
            init_time: protocol_time(),
        }
    }

    fn session_id(&self) -> u64 {
        self.session_id
    }

    // Add first packet to this session.
    // Preconditions:
    // - session ID must match
    // - timeout for first packet receive must not have passed
    fn add_first_packet(mut self, packet: FirstPacket) -> InProgressSession {
        // Moving owned non-copiable values between enum variants:
        // https://rust-unofficial.github.io/patterns/idioms/mem-replace.html
        debug_assert_eq!(self.session_id, packet.session_id);
        debug_assert!(protocol_time() - self.init_time < 35);
        // Sort packets by sequence number
        self.packet_buf
            .sort_unstable_by(|a, b| a.sequence_number.cmp(&b.sequence_number));
        // Try decrypting pending packets if possible
        if self.packet_buf[0].sequence_number == packet.sequence_number + 1 {
            todo!()
        }

        InProgressSession {
            sender_pk: packet.sender_pk,
            session_id: self.session_id,
            session_extensions: packet.session_extensions,
            sequence_number_start: packet.sequence_number,
            command_buf: packet.decrypted_data,
            out_of_order_packet_buffer: self.packet_buf,
            last_packet_time: packet.send_time,
            seq_to_make_progress: packet.sequence_number + 1,
            crypto_ctx: packet.crypto_ctx,
        }
    }

    /// Checks if progress timeout has occured. More specifically,
    /// progress means packet decryption.
    /// Progress must be made at least every 40s
    fn progress_timeout(&self) -> bool {
        let t = protocol_time();
        // Protect against bad values
        if self.init_time > t {
            false
        } else {
            t - self.init_time > 40
        }
    }

    /// Time first packet for this session arrived
    fn progress_time(&self) -> u32 {
        self.init_time
    }

    fn add_packet(&mut self, packet: EncryptedPacket) {
        debug_assert_eq!(self.session_id(), packet.session_id);
        debug_assert!(!(protocol_time() - self.progress_time() > 45));
        self.packet_buf.push(packet);
    }
}

struct InProgressSession {
    sender_pk: PublicKey,
    session_id: u64,
    session_extensions: SessionExtensions,
    // sequence number of first packet is always 0 - TODO(thesis): it is
    // probably a good idea to allow packet numbers to start from
    // arbitrary value, as long as they will not overflow the counter
    sequence_number_start: u64,
    command_buf: Vec<u8>,
    // packet sequence ID needed to make progress on decryption
    seq_to_make_progress: u64,
    out_of_order_packet_buffer: Vec<EncryptedPacket>,
    last_packet_time: u32,
    crypto_ctx: CryptoCtx,
}

impl InProgressSession {
    fn from_first_packet(packet: FirstPacket) -> Self {
        InProgressSession {
            sender_pk: packet.sender_pk,
            session_id: packet.sequence_number,
            session_extensions: packet.session_extensions,
            sequence_number_start: packet.sequence_number,
            command_buf: packet.decrypted_data,
            out_of_order_packet_buffer: Vec::new(),
            last_packet_time: packet.send_time,
            seq_to_make_progress: packet.sequence_number + 1,
            crypto_ctx: packet.crypto_ctx,
        }
    }

    fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Checks if progress timeout has occured. More specifically,
    /// progress means packet decryption.
    /// Progress must be made at least every 40s
    fn progress_timeout(&self) -> bool {
        let t = protocol_time();
        // Protect against bad values
        if self.last_packet_time > t {
            false
        } else {
            t - self.last_packet_time > 40
        }
    }

    /// Time a packet was last successfully decrypted
    fn progress_time(&self) -> u32 {
        self.last_packet_time
    }

    fn add_packet(&mut self, packet: EncryptedPacket) {
        debug_assert_eq!(self.session_id(), packet.session_id);
        debug_assert!(!(protocol_time() - self.progress_time() > 45));
        // Try decrypt
        if packet.sequence_number == self.seq_to_make_progress {
            let len_before = self.command_buf.len();
            match packet.try_decrypt(&mut self.crypto_ctx, &mut self.command_buf) {
                Ok(time) => {
                    if packet_timeout(time) {
                        // Discard the packet
                        self.command_buf.truncate(len_before);
                        eprintln!(" packet too old")
                    } else {
                        self.seq_to_make_progress += 1;
                        // TODO: try decrypting more packets
                    }
                }
                Err(e) => eprintln!(" - packet decryption error: {:?}", e),
            }
        } else {
            self.out_of_order_packet_buffer.push(packet);
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum PacketError {
    Corrupt,
    WrongSession,
    NewSession,
    WrongPacketType,
    UnknownPacketType,
    CryptoErr(HpkeError),
    UnknownExtensions,
    Incomplete,
    TooOld,
}

struct Receiver {
    socket: UdpSocket,
    sender_pks: Vec<PublicKey>,
    receiver_sk: PrivateKey,
    uninit_sessions: Vec<UninitSession>,
    in_progress_sessions: Vec<InProgressSession>,
    packet_buf: [u8; MAX_PACKET_SIZE as usize],
}

impl Receiver {
    fn new(socket: UdpSocket, sender_pks: Vec<PublicKey>, receiver_sk: PrivateKey) -> Self {
        Receiver {
            socket,
            sender_pks,
            receiver_sk,
            packet_buf: [0; MAX_PACKET_SIZE as usize],
            uninit_sessions: Vec::new(),
            in_progress_sessions: Vec::new(),
        }
    }

    fn receive_loop(&mut self) {
        loop {
            let (len, addr) = self.socket.recv_from(&mut self.packet_buf).unwrap();
            eprint!("packet from {}", addr);

            // Packet processing steps:
            // 1. determine type:
            //    - first
            //    - regular
            // 2. parse:
            //    - if error, discard and log reason
            // 3. find session with matching session id
            //    - check if timeout occured
            // 4. hand over packet to that session

            // Packet must belong to one of the known types
            let packet_type = match PacketType::try_from(self.packet_buf[0]) {
                Ok(p) => p,
                Err(_) => {
                    eprintln!(" - unrecognized packet type");
                    continue;
                }
            };
            match packet_type {
                PacketType::FirstData => {
                    // TODO(refactor): don't decrypt the packet,
                    // hand it over immediately to the session, it will know
                    // whether it is worth decrypting
                    if self.packet_buf.len() < MIN_FIRST_PACKET_LEN as usize {
                        eprintln!(" - packet too short: {}", self.packet_buf.len());
                        continue;
                    }
                    let first_packet = match FirstPacket::try_from_buf(
                        &mut self.packet_buf[1..],
                        &self.sender_pks,
                        &self.receiver_sk,
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!(" - failed to parse: {:?}", e);
                            continue;
                        }
                    };
                    let mut insert = None;
                    let mut remove = None;
                    for (i, s) in self.uninit_sessions.iter_mut().enumerate() {
                        if s.session_id() == first_packet.session_id() {
                            // This is the only place where session timeouts are
                            // checked. So old sessions will only be discarded when
                            // a packet arrives with a matching session ID.
                            if s.progress_timeout() {
                                eprintln!(
                                    " - session timeout occured, putting packet in a new session"
                                );
                                // Put it in a new session and destroy the old session
                                insert = Some(InProgressSession::from_first_packet(first_packet));
                                remove = Some(i);
                                break;
                            }
                            break;
                        }
                    }
                    match insert {
                        Some(s) => {
                            self.uninit_sessions.remove(remove.unwrap());
                            self.in_progress_sessions.push(s)
                        }
                        None => (),
                    }
                }
                PacketType::RegularData => {
                    if self.packet_buf.len() < MIN_PACKET_LEN as usize {
                        eprintln!(" - packet too short: {}", self.packet_buf.len());
                        continue;
                    }
                    let packet = match EncryptedPacket::try_from_buf(
                        &mut self.packet_buf[1..],
                        PacketType::RegularData,
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!(" - failed to parse: {:?}", e);
                            continue;
                        }
                    };
                    let mut insert = None;
                    let mut remove = None;
                    for (i, s) in self.in_progress_sessions.iter_mut().enumerate() {
                        if s.session_id() == packet.session_id {
                            // This is the only place where session timeouts are
                            // checked. So old sessions will only be discarded when
                            // a packet arrives with a matching session ID.
                            if s.progress_timeout() {
                                eprintln!(
                                    " - session timeout occured, putting packet in a new session"
                                );
                                // Put it in a new session and destroy the old session
                                insert = Some(UninitSession::from_middle_packet(packet));
                                remove = Some(i);
                                break;
                            }
                            break;
                        }
                    }
                    match insert {
                        Some(s) => {
                            self.in_progress_sessions.remove(remove.unwrap());
                            self.uninit_sessions.push(s)
                        }
                        None => (),
                    }
                }
                PacketType::LastData => {
                    if self.packet_buf.len() < MIN_PACKET_LEN as usize {
                        eprintln!(" - packet too short: {}", self.packet_buf.len());
                        continue;
                    }
                    todo!();
                }
            }
        }
    }
}
