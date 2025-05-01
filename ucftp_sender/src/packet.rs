use std::cmp::min;

use hpke::{Serializable, aead::AeadCtxS};
use log::{debug, trace};
use rand::{CryptoRng, Rng};
use ucftp_shared::{
    ChosenAead, ChosenKdf, ChosenKem, EncappedKey, MIN_FIRST_PACKET_OVERHEAD, PROTOCOL_IDENTIFIER,
    PacketType, SessionExtensions, protocol_time,
    serialise::{BufSerialize, dump_le},
};

const FEC_PACKET_OVERHEAD: u16 = 1 // packet type
    + 8  // session ID
    + 4; // FEC packet header

pub struct PacketIter {
    session_id: u64,
    // actually, u48
    packet_sequence_number: u64,
    protocol_message: Vec<u8>,
    protocol_message_used: usize,
    crypto_ctx: AeadCtxS<ChosenAead, ChosenKdf, ChosenKem>,
    encapped_key: EncappedKey,
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
            packet_size,
            regular_packet_data_size: packet_size
                - 16 // auth tag
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
        let aad_end = self.packet_buffer.len();
        // Only the first packet has time field
        if self.packet_sequence_number == 1 {
            // Send time. TODO(thesis): do we really need to encrypt the time?
            // If we do not encrypt it, we get no benefit. Time still must be verified
            // to be trustworthy, so there is no harm in hiding it
            let t: u32 = protocol_time();
            self.packet_buffer.extend_from_slice(&t.to_le_bytes());
        }
        let packet_overhead = self.packet_buffer.len() as u16 + 16;
        let body_len = min(
            self.protocol_message.len() - self.protocol_message_used,
            (self.packet_size - packet_overhead) as usize,
        );
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
        let aad_end = buf.len();
        // Only the first packet has time field
        if self.packet_sequence_number == 1 {
            let t: u32 = protocol_time();
            buf.extend_from_slice(&t.to_le_bytes());
        }
        let packet_overhead = (buf.len() - buf_start) as u16 + 16;
        let body_len = min(
            self.protocol_message.len() - self.protocol_message_used,
            (self.packet_size - packet_overhead) as usize,
        );
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
            // Number of extensions
            self.packet_buffer.push(0);
            let start_idx = self.packet_buffer.len();
            for _ in 0..size_of::<EncappedKey>() {
                self.packet_buffer.push(0);
            }
            self.encapped_key
                .write_exact(&mut self.packet_buffer[start_idx..]);
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

    pub fn session_id(&self) -> u64 {
        self.session_id
    }
}

pub struct FecPacketIter {
    session_id: u64,
    packets: Vec<raptorq::EncodingPacket>,
    packets_sent: usize,
}

impl FecPacketIter {
    /// If there is only one packet in session, returns that packet
    pub fn new(
        rng: &mut impl CryptoRng,
        mut protocol_message: Vec<u8>,
        mut crypto_ctx: AeadCtxS<ChosenAead, ChosenKdf, ChosenKem>,
        encapped_key: EncappedKey,
        packet_size: u16,
        fec_overhead_percent: u16,
    ) -> (Self, Vec<u8>) {
        let session_id: u64 = rng.random();
        let first_packet_overhead = MIN_FIRST_PACKET_OVERHEAD
            + 1   // extension type
            + 12; // extension (raptorq config)
        let max_first_packet_data_size = packet_size - first_packet_overhead;
        debug_assert!(max_first_packet_data_size as usize >= protocol_message.len());

        let mut first_packet = Vec::with_capacity(packet_size as usize);
        // Protocol identifier
        first_packet.extend_from_slice(PROTOCOL_IDENTIFIER);
        let start_idx = first_packet.len();
        for _ in 0..size_of::<EncappedKey>() {
            first_packet.push(0);
        }
        encapped_key.write_exact(&mut first_packet[start_idx..]);
        // Number of extensions
        first_packet.push(1);
        // Encrypt the remaining data
        // TODO: encrypt the whole thing, TODO(thesis): AAD is session ID
        let fec_encoder = {
            let auth_tag = crypto_ctx
                .seal_in_place_detached(
                    &mut protocol_message[max_first_packet_data_size as usize..],
                    &session_id.to_le_bytes(),
                )
                .unwrap();
            debug!(
                "encrypted the remaining message: {} bytes",
                max_first_packet_data_size,
            );
            // Auth tag
            let data_end = protocol_message.len();
            for _ in 0..16u8 {
                protocol_message.push(0);
            }
            auth_tag.write_exact(&mut protocol_message[data_end..]);
            raptorq::Encoder::with_defaults(
                &protocol_message[max_first_packet_data_size as usize..],
                packet_size - FEC_PACKET_OVERHEAD,
            )
        };
        let ext = SessionExtensions::RaptorQ(fec_encoder.get_config());
        ext.serialize_to_buf(&mut first_packet);

        // Session ID
        dump_le(&mut first_packet, session_id);
        // Packet sequence number is a u48 stored in u64
        first_packet.extend_from_slice(&0u64.to_le_bytes()[..6]);
        let aad_end = first_packet.len();
        // Time
        let t: u32 = protocol_time();
        first_packet.extend_from_slice(&t.to_le_bytes());

        let body_len = max_first_packet_data_size as usize;
        // Body. Encryption works in-place, so we first write plaintext data to
        // the buffer and then encrypt it
        first_packet.extend_from_slice(&protocol_message[..body_len]);
        let (aad, data) = first_packet.split_at_mut(aad_end);
        let auth_tag = crypto_ctx.seal_in_place_detached(data, aad).unwrap();
        trace!(
            "encrypted {} bytes, AAD len {} bytes",
            max_first_packet_data_size + 4,
            aad_end
        );
        // Auth tag
        let data_end = first_packet.len();
        for _ in 0..16u8 {
            first_packet.push(0);
        }
        auth_tag.write_exact(&mut first_packet[data_end..]);

        let packets = {
            let source_packets = (protocol_message.len() - max_first_packet_data_size as usize)
                .div_ceil(packet_size as usize) as u32;
            // TODO(thesis): what to do if there is only one packet? Do we add another
            // FEC packet always or only if fec_overhead_percent >= 100? 50?
            fec_encoder.get_encoded_packets(source_packets * fec_overhead_percent as u32 / 100)
        };

        (
            Self {
                session_id,
                packets,
                packets_sent: 0,
            },
            first_packet,
        )
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// True = success, false = fail. Same as Some() and None for next_packet()
    /// buf does not have to be empty
    pub fn next_packet_buf(&mut self, buf: &mut Vec<u8>) -> bool {
        if self.packets_sent == self.packets.len() {
            return false;
        }

        let packet = &self.packets[self.packets_sent];
        // Serialize manually. Taken from:
        // https://github.com/cberner/raptorq/blob/v2.0.0/src/base.rs#L85
        buf.push(PacketType::ErrorCorrection as u8);
        buf.extend_from_slice(&packet.payload_id().serialize());
        buf.extend_from_slice(packet.data());
        self.packets_sent += 1;

        true
    }
}
