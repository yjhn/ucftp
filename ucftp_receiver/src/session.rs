use std::cmp::Ordering;
use std::time::Instant;

use hpke::Deserializable;
use hpke::HpkeError;
use hpke::aead::AeadCtxR;
use hpke::aead::AeadTag;
use hpke::aead::AesGcm128;
use log::{debug, error, info, trace, warn};
use ucftp_shared::serialise::*;
use ucftp_shared::*;

use crate::message::CommandExecutor;

type CryptoCtx = AeadCtxR<ChosenAead, ChosenKdf, ChosenKem>;

// Packet timeout in seconds. This applies to packet send time,
// to prevent replay attacks. Because protocol time uses UTC as base,
// DST changes do not alter the protocol time, so we don't have to
// tolerate them.
// TODO(thesis): add this reasoning
const PACKET_SEND_TIMEOUT: u32 = 400;
// Progress timeout in seconds: how much time is allowed to pass between session
// packet decryptions before discarding the session
const PROGRESS_TIMEOUT: u64 = 40;

const MIN_FIRST_PACKET_LEN: u16 = 6 // protocol ID
    + 32  // encapped key
    + 1   // number of extensions
    + 8   // session ID
    + 6   // sequence number
    + 4   // send time
    + 9   // at least message len + 1 byte of actual content
    + 16; // auth tag
const MIN_PACKET_LEN: u16 = 1 // packet type
    + 8   // session ID
    + 6   // sequence number
    + 4   // send time
    + 9   // at least message len + 1 byte of actual content
    + 16; // auth tag

fn packet_send_timeout(t: u32) -> bool {
    let time = protocol_time();
    // We don't allow time far into the future.
    // Allowing time in the future means that if a sender sends a packet with
    // time far in the future, that packet will be valid for a long time
    time.abs_diff(t) > PACKET_SEND_TIMEOUT
}

// Packet with its header parsed, but body still encrypted
// Only non-first packet will ever be put in this state
pub struct EncryptedPacket {
    packet_type: PacketType,
    session_id: u64,
    sequence_number: u64,
    encrypted_data: Box<[u8]>,
    auth_tag: AeadTag<AesGcm128>,
}

impl EncryptedPacket {
    #[must_use]
    pub fn try_from_buf(packet: &[u8], p_type: PacketType) -> Result<Self, PacketError> {
        debug_assert_ne!(p_type, PacketType::FirstData);
        if packet.len() < MIN_PACKET_LEN as usize {
            return Err(PacketError::Incomplete);
        }
        let mut packet_used = 0;

        // Session ID
        let session_id = u64_from_le_bytes(&packet[packet_used..]);
        packet_used += 8;

        // Sequence number
        let sequence_number = seq_deser(&packet[packet_used..]);
        packet_used += 6;

        let buf_tag_start = packet.len() - 16;
        // let (_aad, data_tag) = packet.split_at(packet_used);
        let auth_tag = AeadTag::from_bytes(&packet[buf_tag_start..]).unwrap();

        // Allocate storage for the protocol message
        let encrypted_data = Box::from(&packet[packet_used..buf_tag_start]);

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
    #[must_use]
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
                let time = u32_from_le_bytes(&self.encrypted_data);
                if packet_send_timeout(time) {
                    Err(PacketError::TooOld)
                } else {
                    buf.extend_from_slice(&self.encrypted_data[4..]);
                    Ok(time)
                }
            }
            Err(e) => {
                // Clean up AAD
                buf.truncate(buf.len() - 15);
                Err(PacketError::CryptoErr(e))
            }
        }
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }
}

pub struct UninitSession {
    session_id: u64,
    // No packets can be decrypted without the first packet
    // TODO(thesis): mention this limitation and that it cannot be
    // removed without relying on possibly attacker-controlled and unverified
    // data (because we cannot verify contents without the keys)
    packet_buf: Vec<EncryptedPacket>,
    // Packet send time is encrypted. Even if it was not encrypted, we
    // could not trust it, because we can't verify its correctness until
    // we get the first packet. So the timeout logic in this case works
    // as follows: first session packet must arrive within 30 seconds of the
    // first received packet. Otherwise this session is discarded
    init_time: Instant,
}

impl UninitSession {
    pub fn from_middle_packet(packet: EncryptedPacket) -> Self {
        UninitSession {
            session_id: packet.session_id,
            packet_buf: vec![packet],
            init_time: Instant::now(),
        }
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Checks if progress timeout has occured. More specifically,
    /// progress means packet decryption.
    pub fn progress_timeout(&self) -> bool {
        let t = Instant::now();
        self.progress_timeout_from(t)
    }

    pub fn progress_timeout_from(&self, now: Instant) -> bool {
        (now - self.progress_time()).as_secs() > PROGRESS_TIMEOUT
    }

    /// Time first packet for this session arrived
    pub fn progress_time(&self) -> Instant {
        self.init_time
    }

    pub fn add_packet(&mut self, packet: EncryptedPacket) {
        debug_assert_eq!(self.session_id(), packet.session_id);
        debug_assert!((Instant::now() - self.progress_time()).as_secs() < PROGRESS_TIMEOUT + 5);
        trace!(
            "added packet {} to uninit session {}",
            packet.sequence_number, self.session_id
        );
        self.packet_buf.push(packet);
    }
}

pub struct InProgressSession {
    // Will only be needed if rekeying is implemented
    sender_pk: PublicKey,
    session_id: u64,
    session_extensions: SessionExtensions,
    // sequence number of first packet is always 0 - TODO(thesis): it is
    // probably a good idea to allow packet numbers to start from
    // arbitrary value, as long as they will not overflow the counter - or
    // it could overflow the counter and we could check that the seq is
    // 0 < seq < start || progress < seq
    sequence_number_start: u64,
    command_buf: Vec<u8>,
    // packet sequence ID needed to make progress on decryption
    seq_to_make_progress: u64,
    out_of_order_packet_buffer: Vec<EncryptedPacket>,
    last_packet_time: Instant,
    crypto_ctx: CryptoCtx,
}

impl InProgressSession {
    // Try decoding and decrypting the first session packet. May overwrite
    // encrypted data, so buf must not be read from after calling this
    #[must_use]
    pub fn try_from_init_packet_buf(
        packet: &mut [u8],
        sender_pks: &[PublicKey],
        receiver_sk: &PrivateKey,
    ) -> Result<Self, PacketError> {
        trace!("InProgressSession being created");
        let now = Instant::now();
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
        let auth_tag = AeadTag::from_bytes(&packet[buf_tag_start..]).unwrap();
        let (aad, data_tag) = packet.split_at_mut(packet_used);
        let ciphertext = &mut data_tag[..buf_tag_start - packet_used];
        // trace!(
        //     "decrypting: ct len {}, AAD len {}",
        //     ciphertext.len(),
        //     aad.len()
        // );
        match crypto_ctx.open_in_place_detached(ciphertext, aad, &auth_tag) {
            Ok(_) => (),
            Err(e) => return Err(PacketError::CryptoErr(e)),
        }

        let send_time = u32_from_le_bytes(&packet[packet_used..]);
        packet_used += 4;
        if packet_send_timeout(send_time) {
            return Err(PacketError::TooOld);
        }

        // Allocate storage for the protocol message
        let decrypted_data = Vec::from(&packet[packet_used..buf_tag_start]);

        Ok(InProgressSession {
            sender_pk,
            session_id,
            session_extensions: SessionExtensions::empty(),
            crypto_ctx,
            sequence_number_start: sequence_number,
            command_buf: decrypted_data,
            seq_to_make_progress: sequence_number + 1,
            out_of_order_packet_buffer: Vec::new(),
            last_packet_time: now,
        })
    }

    fn inc_progress_seq(&mut self) {
        self.seq_to_make_progress += 1;
        // trace!(
        //     "increased seq to {} for session {}",
        //     self.seq_to_make_progress, self.session_id
        // );
    }

    // Merge an UninitSession into this one.
    // Preconditions:
    // - session IDs must match
    // - progress timeout must not have passed
    // - self must only have the first packet (otherwise all remaining ones
    //   will be lost)
    // - self must not be older than other
    #[must_use]
    pub fn merge(&mut self, mut uninit_session: UninitSession, now: Instant) -> SessionStatus {
        debug_assert_eq!(self.session_id, uninit_session.session_id);
        debug_assert!((Instant::now() - self.progress_time()).as_secs() < PROGRESS_TIMEOUT + 5);
        debug_assert!(self.out_of_order_packet_buffer.is_empty());
        debug_assert!(self.last_packet_time >= uninit_session.init_time);
        // Sort packets by sequence number
        uninit_session
            .packet_buf
            .sort_unstable_by(|a, b| a.sequence_number.cmp(&b.sequence_number));
        // Try decrypting pending packets if possible
        while uninit_session.packet_buf[0].sequence_number == self.seq_to_make_progress {
            // TODO: use VecDequeue or smth similar for faster front pops
            self.decrypt_packet(uninit_session.packet_buf.remove(0), now);
        }

        self.out_of_order_packet_buffer = uninit_session.packet_buf;

        self.session_status()
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Checks if progress timeout has occured. More specifically,
    /// progress means packet decryption.
    pub fn progress_timeout(&self) -> bool {
        let t = Instant::now();
        self.progress_timeout_from(t)
    }

    pub fn progress_timeout_from(&self, now: Instant) -> bool {
        (now - self.progress_time()).as_secs() > PROGRESS_TIMEOUT
    }

    /// Time a packet was last successfully decrypted
    pub fn progress_time(&self) -> Instant {
        self.last_packet_time
    }

    fn decrypt_packet(&mut self, packet: EncryptedPacket, now: Instant) {
        let seq = packet.sequence_number;
        match packet.try_decrypt(&mut self.crypto_ctx, &mut self.command_buf) {
            Ok(_time) => {
                trace!(
                    "added decrypted packet {} to in-progress session {}",
                    seq, self.session_id
                );
                self.last_packet_time = now;
                self.inc_progress_seq();
            }
            Err(e) => error!("packet decryption error: {:?}", e),
        }
    }

    #[must_use]
    pub fn add_packet(&mut self, packet: EncryptedPacket, now: Instant) -> SessionStatus {
        debug_assert_eq!(self.session_id(), packet.session_id);
        debug_assert!((Instant::now() - self.progress_time()).as_secs() < 45);
        // Try decrypt
        match self.seq_to_make_progress.cmp(&packet.sequence_number) {
            Ordering::Less => {
                trace!(
                    "adding packet {} to in-progress session {} out-of-order buffer",
                    packet.sequence_number, self.session_id
                );
                self.out_of_order_packet_buffer.push(packet);
                SessionStatus::Incomplete
            }
            Ordering::Equal => {
                self.decrypt_packet(packet, now);
                self.session_status()
            }
            Ordering::Greater => {
                // Irrelevant packet number. Possibly duplicate. Discard
                trace!(
                    "possibly duplicate packet {} of session {}",
                    packet.sequence_number, self.session_id
                );
                SessionStatus::Incomplete
            }
        }
    }

    /// Check if this session is complete
    // TODO(thesis): add that total length field really helps with detecting when
    // the command has been fully received
    #[must_use]
    pub fn session_status(&self) -> SessionStatus {
        // Strategies to check if complete:
        // - all packet numbers first..=last have been received (last here means
        //   packet with last session packet type)
        // - command parsing does not fail
        match CommandExecutor::new(&self.command_buf, self.session_id) {
            Ok(command) => {
                debug!("received full command for session {}", self.session_id());
                SessionStatus::Complete(command)
            }
            Err(e) => match e {
                DeserializationError::CommandLenExpected | DeserializationError::LengthMismatch => {
                    // trace!("failed attempt to deserialize session: {:?}", e);
                    SessionStatus::Incomplete
                }
                err => {
                    error!("error parsing command: {:?}", err);
                    SessionStatus::Corrupt
                }
            },
        }
    }
}

pub enum SessionStatus {
    Complete(CommandExecutor),
    Incomplete,
    Corrupt,
}

#[derive(Debug, Clone, Copy)]
pub enum PacketError {
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
