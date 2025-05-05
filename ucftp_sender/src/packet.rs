use std::cmp::min;

use hpke::{Serializable, aead::AeadCtxS};
use log::trace;
use rand::{CryptoRng, Rng};
use ucftp_shared::{
    Aes128EcbEnc, ChosenAead, ChosenKdf, ChosenKem, EncappedKey, MIN_FIRST_PACKET_OVERHEAD,
    PROTOCOL_IDENTIFIER, PacketSeqKey, PacketType, SessionExtensions, protocol_time,
    raptorq_crypto_seq,
    serialise::{BufSerialize, dump_le},
};

const FEC_PACKET_OVERHEAD: u16 = 1 // packet type
    + 8   // session ID
    + 4   // FEC packet header
    + 16; // auth tag

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
    aes_ecb: Aes128EcbEnc,
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
        let key = crypto_ctx.regular_packet_seq_key();
        let aes_ecb = Aes128EcbEnc::from_key(&key);
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
            aes_ecb,
        }
    }

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
            // Send time
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

        // Encrypt sequence number
        let (seq, ct) = self.packet_buffer[aad_end - 6..].split_at_mut(6);
        self.aes_ecb.encrypt_decrypt_seq(seq, ct);
    }

    pub fn next_packet(&mut self) -> Option<&[u8]> {
        if self.protocol_message_used == self.protocol_message.len() {
            return None;
        }

        if self.packet_sequence_number == 0 {
            // First packet
            // Protocol identifier
            self.packet_buffer.extend_from_slice(PROTOCOL_IDENTIFIER);
            // TODO: if session has only one packet, we don't need packet seq. But
            // then we need to indicate that this is the only packet
            // Maybe use 3 most significant bits of extension count to indicate packet
            // type, then we don't need any additional bytes
            // Number of extensions
            self.packet_buffer.push(0);
            let start_idx = self.packet_buffer.len();
            for _ in 0..32 {
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
    crypto_ctx: AeadCtxS<ChosenAead, ChosenKdf, ChosenKem>,
    aes_ecb: Aes128EcbEnc,
}

impl FecPacketIter {
    /// Returns (FecPacketIter, first_packet)
    pub fn new(
        rng: &mut impl CryptoRng,
        protocol_message: Vec<u8>,
        mut crypto_ctx: AeadCtxS<ChosenAead, ChosenKdf, ChosenKem>,
        encapped_key: EncappedKey,
        packet_size: u16,
        fec_overhead_percent: u16,
    ) -> (Self, Vec<u8>) {
        let session_id: u64 = rng.random();
        let first_packet_overhead = MIN_FIRST_PACKET_OVERHEAD
            + 1   // extension type
            + 12; // extension (raptorq config)
        let first_packet_data_size = (packet_size - first_packet_overhead) as usize;
        debug_assert!((first_packet_data_size as usize) < protocol_message.len());

        let mut first_packet = Vec::with_capacity(packet_size as usize);
        // Protocol identifier
        first_packet.extend_from_slice(PROTOCOL_IDENTIFIER);

        // Number of extensions
        first_packet.push(1);
        // Extensions
        let oti = raptorq::ObjectTransmissionInformation::with_defaults(
            (protocol_message.len() - first_packet_data_size) as u64,
            packet_size - FEC_PACKET_OVERHEAD,
        );
        let ext = SessionExtensions::RaptorQ(oti);
        ext.serialize_to_buf(&mut first_packet);

        // Encapped key
        let start_idx = first_packet.len();
        for _ in 0..32u8 {
            first_packet.push(0);
        }
        encapped_key.write_exact(&mut first_packet[start_idx..]);

        // Session ID
        // TODO: maybe also encrypt session ID of first packet?
        // pros:
        // - less info exposed
        // cons:
        // - more work has to be done by receiver to drop irrelevant (duplicate)
        //   packets
        dump_le(&mut first_packet, session_id);

        // This is AAD end.
        let aad_end = first_packet.len();

        // Time
        let t: u32 = protocol_time();
        first_packet.extend_from_slice(&t.to_le_bytes());

        // Body. Encryption works in-place, so we first write plaintext data to
        // the buffer and then encrypt it
        first_packet.extend_from_slice(&protocol_message[..first_packet_data_size as usize]);
        let (aad, data) = first_packet.split_at_mut(aad_end);

        let auth_tag = crypto_ctx.seal_in_place_detached(data, aad).unwrap();
        trace!(
            "encrypted {} bytes, AAD len {} bytes",
            data.len(),
            aad.len()
        );

        // Auth tag
        let data_end = first_packet.len();
        for _ in 0..16u8 {
            first_packet.push(0);
        }
        auth_tag.write_exact(&mut first_packet[data_end..]);

        // Encrypt the remaining data
        let fec_encoder = raptorq::Encoder::new(&protocol_message[first_packet_data_size..], oti);
        let packets = {
            let source_packets = (protocol_message.len() - first_packet_data_size as usize)
                .div_ceil(packet_size as usize) as u32;
            fec_encoder.get_encoded_packets(source_packets * fec_overhead_percent as u32 / 100)
        };

        let key = crypto_ctx.fec_packet_seq_key();
        let aes_ecb = Aes128EcbEnc::from_key(&key);
        (
            Self {
                session_id,
                packets,
                packets_sent: 0,
                crypto_ctx,
                aes_ecb,
            },
            first_packet,
        )
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// True = success, false = fail. Same as Some() and None for next_packet()
    /// buf does not have to be empty, but it will be cleared
    pub fn next_packet_buf(&mut self, buf: &mut Vec<u8>) -> bool {
        if self.packets_sent == self.packets.len() {
            return false;
        }

        buf.clear();
        let packet = &self.packets[self.packets_sent];
        // Serialize manually. Taken from:
        // https://github.com/cberner/raptorq/blob/v2.0.0/src/base.rs#L85
        buf.push(PacketType::ErrorCorrection as u8);
        buf.extend_from_slice(&self.session_id.to_le_bytes());
        buf.extend_from_slice(&packet.payload_id().serialize());
        let aad_end = buf.len();
        buf.extend_from_slice(packet.data());

        // Encrypt
        let (aad, data) = buf.split_at_mut(aad_end);
        let seq = raptorq_crypto_seq(&packet.payload_id());

        let auth_tag = self
            .crypto_ctx
            .seal_in_place_detached_seq(data, aad, seq)
            .unwrap();
        trace!(
            "encrypted {} bytes, AAD len {} bytes",
            data.len(),
            aad.len()
        );

        // Auth tag
        let data_end = buf.len();
        for _ in 0..16u8 {
            buf.push(0);
        }
        auth_tag.write_exact(&mut buf[data_end..]);

        // Encrypt seq
        let (seq, other) = buf[9..].split_at_mut(4);
        self.aes_ecb.encrypt_decrypt_seq(seq, other);

        self.packets_sent += 1;

        true
    }
}
