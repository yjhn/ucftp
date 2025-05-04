use std::cmp::Ordering;
use std::time::Instant;

use hpke::Deserializable;
use hpke::HpkeError;
use hpke::aead::AeadCtxR;
use hpke::aead::AeadTag;
use hpke::aead::AesGcm128;
use log::error;
use log::{debug, trace};
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

pub const MIN_FIRST_PACKET_LEN: u16 = 6 // protocol ID
    + 32  // encapped key
    + 1   // number of extensions
    + 8   // session ID
    + 6   // sequence number
    + 4   // send time
    + 9   // at least message len + 1 byte of actual content
    + 16; // auth tag
pub const MIN_PACKET_LEN: u16 = 1 // packet type
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
    encrypted_data: Box<[u8]>,
    auth_tag: AeadTag<AesGcm128>,
}

impl EncryptedPacket {
    #[must_use]
    pub fn try_from_buf(packet: &mut [u8], p_type: PacketType) -> Result<Self, PacketError> {
        debug_assert_ne!(p_type, PacketType::FirstData);
        if packet.len() < MIN_PACKET_LEN as usize {
            return Err(PacketError::Incomplete);
        }
        let mut packet_used = 0;

        // Session ID
        let session_id = u64_from_le_bytes(&packet[packet_used..]);
        packet_used += 8;

        // Sequence number cannot be decrypted
        // It takes up first 6 bytes of encypted_data

        let buf_tag_start = packet.len() - 16;
        // let (_aad, data_tag) = packet.split_at(packet_used);
        let auth_tag = AeadTag::from_bytes(&packet[buf_tag_start..]).unwrap();

        // Allocate storage for the protocol message
        let encrypted_data = Box::from(&packet[packet_used..buf_tag_start]);

        Ok(EncryptedPacket {
            auth_tag,
            packet_type: p_type,
            encrypted_data,
            session_id,
        })
    }

    pub fn decrypt_seq(mut self, aes_ecb: &Aes128EcbEnc) -> EncryptedPacketWithSeq {
        // Packet sequence number is a u48 stored in u64
        let (seq, other) = self.encrypted_data.split_at_mut(6);
        aes_ecb.encrypt_decrypt_seq(seq, other);
        let sequence_number = seq_deser(seq);

        EncryptedPacketWithSeq {
            packet_type: self.packet_type,
            session_id: self.session_id,
            sequence_number,
            encrypted_data: self.encrypted_data,
            auth_tag: self.auth_tag,
        }
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }
}

pub struct EncryptedPacketWithSeq {
    packet_type: PacketType,
    session_id: u64,
    sequence_number: u64,
    // Decrypted sequence number takes first 6 bytes
    encrypted_data: Box<[u8]>,
    auth_tag: AeadTag<AesGcm128>,
}

impl EncryptedPacketWithSeq {
    // This will corrupt the packet's buffer, so the packet will become useless
    // either way
    // TODO: create a new type EncryptedPacketWithSeq
    #[must_use]
    pub fn try_decrypt(
        mut self,
        crypto_ctx: &mut CryptoCtx,
        buf: &mut Vec<u8>,
    ) -> Result<(), PacketError> {
        // Recreate AAD, structure:
        // - packet type
        // - session ID
        // - sequence number
        // use buf as scratch space

        buf.push(self.packet_type as u8);
        dump_le(buf, self.session_id);
        // Sequence number
        buf.extend_from_slice(&self.encrypted_data[..6]);

        match crypto_ctx.open_in_place_detached(
            &mut self.encrypted_data[6..],
            &buf[buf.len() - 15..],
            &self.auth_tag,
        ) {
            Ok(_) => {
                // Clean up AAD
                buf.truncate(buf.len() - 15);
                // let time = u32_from_le_bytes(&self.encrypted_data);
                // if packet_send_timeout(time) {
                //     Err(PacketError::TooOld)
                // } else {
                // buf.extend_from_slice(&self.encrypted_data[4..]);
                // Ok(time)
                // }
                buf.extend_from_slice(&self.encrypted_data[6..]);
                Ok(())
            }
            Err(e) => {
                // Clean up AAD
                buf.truncate(buf.len() - 15);
                Err(PacketError::CryptoErr(e))
            }
        }
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
        trace!("added packet to uninit session {}", self.session_id);
        self.packet_buf.push(packet);
    }
}

/// Packet type is alway FEC
pub struct EncryptedRaptorqPacket {
    session_id: u64,
    encrypted_data: Box<[u8]>,
    auth_tag: AeadTag<AesGcm128>,
}

impl EncryptedRaptorqPacket {
    // TODO: maybe use Vec for packet?
    #[must_use]
    pub fn try_from_buf(packet: &mut [u8], session_id: u64) -> Result<Self, PacketError> {
        // TODO: update/customize MIN_PACKET_LEN for various cases. Maybe use
        // associated consts for each packet type?
        if packet.len() < MIN_PACKET_LEN as usize {
            return Err(PacketError::Incomplete);
        }

        // Sequence number cannot be decrypted
        // It takes up first 4 bytes of encypted_data

        let buf_tag_start = packet.len() - 16;
        let auth_tag = AeadTag::from_bytes(&packet[buf_tag_start..]).unwrap();

        // Allocate storage for the protocol message
        let encrypted_data = Box::from(&packet[..buf_tag_start]);

        Ok(EncryptedRaptorqPacket {
            auth_tag,
            encrypted_data,
            session_id,
        })
    }

    pub fn try_decrypt(
        mut self,
        aes_ecb: &Aes128EcbEnc,
        crypto_ctx: &mut CryptoCtx,
    ) -> Result<raptorq::EncodingPacket, PacketError> {
        // Packet sequence number is RaptorQ PayloadId (4 bytes)
        let (seq, other) = self.encrypted_data.split_at_mut(4);
        aes_ecb.encrypt_decrypt_seq(seq, other);
        let seq = seq.first_chunk::<4>().unwrap();
        let payload_id = raptorq::PayloadId::deserialize(seq);

        // Data
        // Recreate AAD, structure:
        // - packet type
        // - session ID
        // - sequence number (PayloadId)
        // use buf as scratch space
        let mut aad = [0; 13];
        aad[0] = PacketType::ErrorCorrection as u8;
        aad[1..9].copy_from_slice(&self.session_id.to_le_bytes());
        aad[9..].copy_from_slice(seq);

        let decryption_seq = raptorq_crypto_seq(&payload_id);
        match crypto_ctx.open_in_place_detached_seq(
            &mut self.encrypted_data[4..],
            &aad,
            &self.auth_tag,
            decryption_seq,
        ) {
            // TODO: maybe use EncodingPacket::deserialize?
            // TODO: store encryped_data and encrpyted seq separately to avoid
            // copying here
            Ok(_) => Ok(raptorq::EncodingPacket::new(
                payload_id,
                self.encrypted_data[4..].into(),
            )),
            Err(e) => Err(PacketError::CryptoErr(e)),
        }
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }
}

pub struct UninitFecSession {
    session_id: u64,
    // No packets can be decrypted without the first packet
    // TODO(thesis): mention this limitation and that it cannot be
    // removed without relying on possibly attacker-controlled and unverified
    // data (because we cannot verify contents without the keys)
    fec_packet_buf: Vec<EncryptedRaptorqPacket>,
    // Packet send time is encrypted. Even if it was not encrypted, we
    // could not trust it, because we can't verify its correctness until
    // we get the first packet. So the timeout logic in this case works
    // as follows: first session packet must arrive within 30 seconds of the
    // first received packet. Otherwise this session is discarded
    init_time: Instant,
}

impl UninitFecSession {
    pub fn from_packet(packet: EncryptedRaptorqPacket, session_id: u64) -> Self {
        UninitFecSession {
            session_id,
            fec_packet_buf: vec![packet],
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

    pub fn add_packet(&mut self, packet: EncryptedRaptorqPacket, session_id: u64) {
        debug_assert_eq!(self.session_id(), session_id);
        debug_assert!((Instant::now() - self.progress_time()).as_secs() < PROGRESS_TIMEOUT + 5);

        trace!("added packet to uninit FEC session {}", self.session_id);
        self.fec_packet_buf.push(packet);
    }
}

pub struct InProgressSession {
    // Will only be needed if rekeying is implemented
    sender_pk: PublicKey,
    session_id: u64,
    // session_extensions: SessionExtensions,
    // sequence number of first packet is always 0 - TODO(thesis): it is
    // probably a good idea to allow packet numbers to start from
    // arbitrary value, as long as they will not overflow the counter - or
    // it could overflow the counter and we could check that the seq is
    // 0 < seq < start || progress < seq
    sequence_number_start: u64,
    command_buf: Vec<u8>,
    // packet sequence ID needed to make progress on decryption
    seq_to_make_progress: u64,
    out_of_order_packet_buffer: Vec<EncryptedPacketWithSeq>,
    last_packet_time: Instant,
    crypto_ctx: CryptoCtx,
    aes_ecb: Aes128EcbEnc,
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
        // if packet.len() < MIN_FIRST_PACKET_LEN as usize {
        //     return Err(PacketError::Incomplete);
        // }

        // Check header
        if &packet[..6] != PROTOCOL_IDENTIFIER {
            return Err(PacketError::WrongPacketType);
        }
        let mut packet_used = 6;

        // Extensions. InProgressSession does not support any
        // TODO(thesis): note that extensions can customize anything after them,
        // that's why they are in front of first packet. Examples:
        // - different field sizes (session ID, seq)
        // - different crypto algorithms
        // - FEC
        if packet[packet_used] > 0 {
            return Err(PacketError::UnknownExtensions);
        }
        packet_used += 1;

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
            None => return Err(PacketError::SenderKeyNotFound),
        };
        packet_used += 32;

        // Session ID
        let session_id = u64_from_le_bytes(&packet[packet_used..]);
        packet_used += 8;

        // Sequence number
        let aes_ecb = Aes128EcbEnc::from_key(&crypto_ctx.regular_packet_seq_key());
        let (seq, other) = packet[packet_used..].split_at_mut(6);
        aes_ecb.encrypt_decrypt_seq(seq, other);
        let sequence_number = seq_deser(seq);
        packet_used += 6;

        // Decrypt data
        // If decryption is unsuccessful, this may corrupt the ciphertext.
        // But since this is the first packet and the key has been
        // successfully decapped, this packet will be discarded if we fail
        // decryption anyway, so this doesn't matter
        let auth_tag_start = packet.len() - 16;
        let auth_tag = AeadTag::from_bytes(&packet[auth_tag_start..]).unwrap();
        let (aad, data_tag) = packet.split_at_mut(packet_used);
        let ciphertext = &mut data_tag[..auth_tag_start - packet_used];
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
        let decrypted_data = Vec::from(&packet[packet_used..auth_tag_start]);

        let aes_ecb = Aes128EcbEnc::from_key(&crypto_ctx.regular_packet_seq_key());

        Ok(InProgressSession {
            sender_pk,
            session_id,
            crypto_ctx,
            sequence_number_start: sequence_number,
            command_buf: decrypted_data,
            seq_to_make_progress: sequence_number + 1,
            out_of_order_packet_buffer: Vec::new(),
            last_packet_time: now,
            aes_ecb,
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
        debug_assert!((now - self.progress_time()).as_secs() < PROGRESS_TIMEOUT + 5);
        debug_assert!(self.out_of_order_packet_buffer.is_empty());
        debug_assert!(self.last_packet_time >= uninit_session.init_time);
        // Sort packets by sequence number
        let mut packets_with_seqs: Vec<EncryptedPacketWithSeq> = uninit_session
            .packet_buf
            .drain(..)
            .map(|p| p.decrypt_seq(&self.aes_ecb))
            .collect();
        packets_with_seqs.sort_unstable_by(|a, b| a.sequence_number.cmp(&b.sequence_number));
        // Try decrypting pending packets if possible
        while !packets_with_seqs.is_empty()
            && packets_with_seqs[0].sequence_number == self.seq_to_make_progress
        {
            // TODO: use VecDequeue or smth similar for faster front pops
            self.decrypt_packet(packets_with_seqs.remove(0), now);
        }

        self.out_of_order_packet_buffer = packets_with_seqs;
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

    fn decrypt_packet(&mut self, packet: EncryptedPacketWithSeq, now: Instant) {
        let seq = packet.sequence_number;
        match packet.try_decrypt(&mut self.crypto_ctx, &mut self.command_buf) {
            Ok(_) => {
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
        debug_assert!((now - self.progress_time()).as_secs() < 45);
        let packet = packet.decrypt_seq(&self.aes_ecb);
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
                // Try decrypting more packets
                // TODO: be more efficient
                self.out_of_order_packet_buffer
                    .sort_unstable_by(|a, b| a.sequence_number.cmp(&b.sequence_number));
                while !self.out_of_order_packet_buffer.is_empty()
                    && self.out_of_order_packet_buffer[0].sequence_number
                        == self.seq_to_make_progress
                {
                    // TODO: use VecDequeue or smth similar for faster front pops
                    let elem = self.out_of_order_packet_buffer.remove(0);
                    self.decrypt_packet(elem, now);
                }

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

    // TODO(thesis): reasons to use/not use FEC:
    // - for:
    //   - packet loss tolerance
    // - against:
    //   - additional computation for encoder and decoder, especially for long
    //     messages
    //   - session timeouts are hard - they cannot rely on progress timeouts,
    //     because decryption is done all at the same time. This means that
    //     it is unclear when session can be declared as timed out - attacker
    //     can feed packets one by one, exhausting receiver's memory. But timeouts
    //     are also necessary in regular situations - sender process can be
    //     killed in the middle of transfer - idea: dynamic timeout based on
    //     the total command length from first packet (the longer the command,
    //     the longer the timeout). Also, there should be a timeout of like 10s
    //     after the first packet for the init packet to arrive
    //   - higher memory usage, as the whole command has to be fully received
    //     before being able to revocer the data. Note that this only applies if
    //     the regular implementation is optimized to not store all the data
    //     in memory (i.e. write file piece by piece as they are received)

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
    /// More packets needed to complete the session
    Incomplete,
    /// Session is useless and should be discarded
    Corrupt,
}

#[derive(Debug, Clone, Copy)]
pub enum PacketError {
    Corrupt,
    WrongSession,
    NewSession,
    ExpectedFecExtension,
    WrongPacketType,
    UnknownPacketType,
    CryptoErr(HpkeError),
    UnknownExtensions,
    /// None of the sender keys worked for decapsulating encapped key
    SenderKeyNotFound,
    Incomplete,
    TooOld,
    DeserializationErr(DeserializationError),
}

pub struct InProgressFecSession {
    // TODO(thesis): to implement rekeying, we would need to split packets into
    // groups with identifiers or possibly by packet number. Without groups or seq
    // identifiers for each packet (including FEC packets), it is impossible to
    // determine which key group packet belongs to
    // Will only be needed if rekeying is implemented
    sender_pk: PublicKey,
    session_id: u64,
    command_buf: Vec<u8>,
    first_packet_time: Instant,
    crypto_ctx: CryptoCtx,
    aes_ecb: Aes128EcbEnc,
    fec_decoder: raptorq::Decoder,
}

impl InProgressFecSession {
    // Try decoding and decrypting the first session packet. May overwrite
    // encrypted data, so buf must not be read from after calling this
    /// To decide whether to create InProgressSession or InProgressFecSession,
    /// caller can look at first (type) and seventh (extension count) bytes
    #[must_use]
    pub fn try_from_init_packet_buf(
        packet: &mut [u8],
        sender_pks: &[PublicKey],
        receiver_sk: &PrivateKey,
    ) -> Result<Self, PacketError> {
        trace!("InProgressFecSession being created");
        let now = Instant::now();
        // if packet.len() < MIN_FIRST_PACKET_LEN as usize {
        //     return Err(PacketError::Incomplete);
        // }

        // Check header
        if &packet[..6] != PROTOCOL_IDENTIFIER {
            return Err(PacketError::WrongPacketType);
        }
        let mut packet_used = 6;
        // Extensions. Currently we only support one: RaptorQ FEC
        // TODO(thesis): move extensions header before encapped key
        let fec_decoder = match packet[packet_used] {
            0 => return Err(PacketError::ExpectedFecExtension),
            1 => {
                // Extension count takes 1 byte
                packet_used += 1;
                match SessionExtensions::try_deserialize_from_buf(&packet[packet_used..]) {
                    Ok((used, ext)) => {
                        packet_used += used;
                        match ext {
                            SessionExtensions::RaptorQ(oti) => raptorq::Decoder::new(oti),
                        }
                    }
                    Err(e) => return Err(PacketError::DeserializationErr(e)),
                }
            }
            _ => return Err(PacketError::UnknownExtensions),
        };
        // TODO: we may read out of bounds later as extensions are present

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
            None => return Err(PacketError::SenderKeyNotFound),
        };
        packet_used += 32;

        // Session ID
        let session_id = u64_from_le_bytes(&packet[packet_used..]);
        packet_used += 8;

        // Decrypt data
        // If decryption is unsuccessful, this may corrupt the ciphertext.
        // But since this is the first packet and the key has been
        // successfully decapped, this packet will be discarded if we fail
        // decryption anyway, so this doesn't matter
        let auth_tag_start = packet.len() - 16;
        let auth_tag = AeadTag::from_bytes(&packet[auth_tag_start..]).unwrap();
        let (aad, ciphertext) = packet[..auth_tag_start].split_at_mut(packet_used);
        trace!(
            "decrypting: ct len {}, AAD len {}",
            ciphertext.len(),
            aad.len()
        );
        if let Err(e) = crypto_ctx.open_in_place_detached(ciphertext, aad, &auth_tag) {
            return Err(PacketError::CryptoErr(e));
        }

        let send_time = u32_from_le_bytes(&packet[packet_used..]);
        packet_used += 4;
        if packet_send_timeout(send_time) {
            return Err(PacketError::TooOld);
        }

        // Allocate storage for the protocol message
        let decrypted_data = Vec::from(&packet[packet_used..auth_tag_start]);

        let key = crypto_ctx.fec_packet_seq_key();
        let aes_ecb = Aes128EcbEnc::from_key(&key);

        Ok(InProgressFecSession {
            sender_pk,
            session_id,
            crypto_ctx,
            command_buf: decrypted_data,
            first_packet_time: now,
            fec_decoder,
            aes_ecb,
        })
    }

    // Merge an UninitSession into this one.
    // Preconditions:
    // - session IDs must match
    // - progress timeout must not have passed
    #[must_use]
    pub fn merge(&mut self, mut uninit_session: UninitFecSession, now: Instant) -> SessionStatus {
        debug_assert_eq!(self.session_id, uninit_session.session_id);
        debug_assert!((now - self.progress_time()).as_secs() < PROGRESS_TIMEOUT + 5);

        for p in uninit_session.fec_packet_buf.drain(..) {
            match p.try_decrypt(&self.aes_ecb, &mut self.crypto_ctx) {
                Ok(p2) => {
                    self.fec_decoder.add_new_packet(p2);
                }
                Err(e) => {
                    error!(
                        "failed to decrypt FEC packet for session {}: {:?}",
                        self.session_id, e
                    );
                }
            }
        }
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
        self.first_packet_time
    }

    // TODO(thesis): reasons to use/not use FEC:
    // - for:
    //   - packet loss tolerance
    // - against:
    //   - additional computation for encoder and decoder, especially for long
    //     messages
    //   - higher memory usage, as the whole command has to be fully received
    //     before being able to revocer the data. Note that this only applies if
    //     the regular implementation is optimized to not store all the data
    //     in memory (i.e. write file piece by piece as they are received)
    #[must_use]
    pub fn add_packet(
        &mut self,
        packet: EncryptedRaptorqPacket,
        session_id: u64,
        now: Instant,
    ) -> SessionStatus {
        debug_assert_eq!(self.session_id(), session_id);
        debug_assert!((now - self.progress_time()).as_secs() < PROGRESS_TIMEOUT + 5);
        trace!(
            "adding FEC packet to in-progress FEC session {}",
            self.session_id
        );
        match packet.try_decrypt(&self.aes_ecb, &mut self.crypto_ctx) {
            Ok(p) => {
                self.fec_decoder.add_new_packet(p);
                self.session_status()
            }
            Err(e) => {
                error!(
                    "failed to decrypt FEC packet for session {}: {:?}",
                    session_id, e
                );
                SessionStatus::Incomplete
            }
        }
    }

    /// Check if this session is complete
    #[must_use]
    pub fn session_status(&mut self) -> SessionStatus {
        // Strategies to check if complete:
        // - all packet numbers first..=last have been received (last here means
        //   packet with last session packet type)
        // - command parsing does not fail
        match self.fec_decoder.get_result() {
            Some(data) => {
                self.command_buf.extend_from_slice(&data);
                match CommandExecutor::new(&self.command_buf, self.session_id) {
                    Ok(command) => {
                        debug!("received full command for session {}", self.session_id());
                        SessionStatus::Complete(command)
                    }
                    Err(e) => match e {
                        DeserializationError::CommandLenExpected
                        | DeserializationError::LengthMismatch => {
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
            None => {
                // TODO: when the full session is received, discard packets destined
                // for the same session for some time (30s?) to prevent creating fake
                // sessions.
                SessionStatus::Incomplete
            }
        }
    }
}
