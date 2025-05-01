use std::fs;
use std::io;
use std::path::Path;
use std::time;

use base64::DecodeSliceError;
use base64::engine::{Engine, general_purpose::STANDARD as BASE64_STANDARD};
use hpke::Deserializable;
use hpke::HpkeError;
use hpke::OpModeR;
use hpke::OpModeS;
use hpke::aead::AeadCtxR;
use hpke::aead::AeadCtxS;
use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use rand_core::CryptoRng;
use serialise::BufSerialize;
use serialise::DeserializationError;

pub mod message;
pub mod serialise;

pub const PROTOCOL_IDENTIFIER: &[u8; 6] = b"UCFTP\x01";
pub const PROTOCOL_INFO: &[u8] = b"UCFTP";
// Equivalent to 2025-01-01 00:00:00 UTC
pub const PROTOCOL_TIME_UNIX_EPOCH_OFFSET: u32 = 1735689600;
pub const RECEIVER_PORT: u16 = 4321;
pub const UDP_HEADER_SIZE: u16 = 8;
pub const IP4_HEADER_SIZE: u16 = 20;
pub const MIN_FIRST_PACKET_HEADER_SIZE: u16 = 6 // protocol identifier
    + 1  // number of extensions (0 here)
    + 32 // encapped key
    + 8  // session ID
    + 6; // packet sequence number
pub const MIN_FIRST_PACKET_OVERHEAD: u16 = MIN_FIRST_PACKET_HEADER_SIZE
    + 4   // time
    + 16; // auth tag

pub type ChosenKem = X25519HkdfSha256;
pub type PrivateKey = <ChosenKem as hpke::Kem>::PrivateKey;
pub type PublicKey = <ChosenKem as hpke::Kem>::PublicKey;
pub type EncappedKey = <ChosenKem as hpke::Kem>::EncappedKey;
pub type ChosenAead = AesGcm128;
pub type ChosenKdf = HkdfSha256;

// TODO(thesis): mention these sizes
const _: () = if size_of::<EncappedKey>() != 32 {
    panic!()
};

const _: () = if size_of::<hpke::aead::AeadTag<AesGcm128>>() != 16 {
    panic!()
};

#[derive(Debug, Clone, Copy)]
pub enum SessionExtensions {
    RaptorQ(raptorq::ObjectTransmissionInformation),
}

impl BufSerialize for SessionExtensions {
    fn serialize_to_buf(self, buf: &mut Vec<u8>) {
        match self {
            SessionExtensions::RaptorQ(oti) => {
                buf.push(1);
                buf.extend_from_slice(&oti.serialize());
            }
        }
    }
}

impl SessionExtensions {
    // pub fn empty() -> Self {
    //     SessionExtensions {}
    // }

    // TODO: allow at most 1 extension for now
    pub fn from_buf(buf: &[u8]) -> Result<Self, DeserializationError> {
        if buf.is_empty() {
            return Err(DeserializationError::ValueExpected);
        }
        match buf[0] {
            // RaptorQ
            0 => {
                if buf.len() < 13 {
                    return Err(DeserializationError::IncompleteValue);
                }
                let oti = raptorq::ObjectTransmissionInformation::deserialize(
                    buf[1..].first_chunk::<12>().unwrap(),
                );
                Ok(Self::RaptorQ(oti))
            }
            _ => Err(DeserializationError::UnknownEnumValue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    FirstData = 0, // - first packet is indicated by protocol identifier
    RegularData = 1,
    LastData,
    ErrorCorrection,
}

impl TryFrom<u8> for PacketType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            b'U' => Ok(PacketType::FirstData),
            1 => Ok(PacketType::RegularData),
            2 => Ok(PacketType::LastData),
            3 => Ok(PacketType::ErrorCorrection),
            _ => Err(()),
        }
    }
}

pub fn protocol_time() -> u32 {
    // SystemTime::now() gives UTC current time.
    // It is not monotonic, which is not ideal
    // Implementation from:
    // https://github.com/jedisct1/rust-coarsetime/blob/0.1.36/src/clock.rs#L84
    let unix_ts_now = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .expect("The system clock is not properly set");

    (unix_ts_now.as_secs() - PROTOCOL_TIME_UNIX_EPOCH_OFFSET as u64) as u32
}

#[derive(Debug)]
pub enum KeyReadError {
    IoError(io::Error),
    /// Public key swapped with private key
    WrongKeyKind,
    /// File is not a recognized key file
    UnrecognizedFile,
    /// File has the required header, but is not there
    FileTooShort,
    /// Key line is too short
    KeyTooShort,
    /// Failed to decode base64 line: too long, wrong chars
    LineFailedDecode(DecodeSliceError),
    /// Failed to create the key from material
    DeserError(HpkeError),
}

pub fn read_sk<P: AsRef<Path>>(path: P) -> Result<PrivateKey, KeyReadError> {
    let file_contents = fs::read_to_string(path).unwrap();
    parse_sk(&file_contents)
}

pub fn read_pk<P: AsRef<Path>>(path: P) -> Result<PublicKey, KeyReadError> {
    let file_contents = fs::read_to_string(path).unwrap();
    parse_pk(&file_contents)
}

fn parse_sk(pem: &str) -> Result<PrivateKey, KeyReadError> {
    let mut buf = [0; 48];
    let mut lines = pem.lines();
    match lines.next() {
        Some("-----BEGIN PRIVATE KEY-----") => (),
        Some("-----BEGIN PUBLIC KEY-----") => return Err(KeyReadError::WrongKeyKind),
        _ => return Err(KeyReadError::UnrecognizedFile),
    }
    match lines.next() {
        Some(l) => match decode_pem_line(l, &mut buf) {
            Ok(len) => {
                if len < 48 {
                    return Err(KeyReadError::KeyTooShort);
                }
            }
            Err(e) => return Err(KeyReadError::LineFailedDecode(e)),
        },

        None => return Err(KeyReadError::UnrecognizedFile),
    }
    match PrivateKey::from_bytes(&buf[16..]) {
        Ok(key) => Ok(key),
        Err(e) => Err(KeyReadError::DeserError(e)),
    }
}

fn parse_pk(pem: &str) -> Result<PublicKey, KeyReadError> {
    let mut buf = [0; 44];
    let mut lines = pem.lines();
    match lines.next() {
        Some("-----BEGIN PUBLIC KEY-----") => (),
        Some("-----BEGIN PRIVATE KEY-----") => return Err(KeyReadError::WrongKeyKind),
        _ => return Err(KeyReadError::UnrecognizedFile),
    }
    match lines.next() {
        Some(l) => match decode_pem_line(l, &mut buf) {
            Ok(len) => {
                if len < 44 {
                    return Err(KeyReadError::KeyTooShort);
                }
            }
            Err(e) => return Err(KeyReadError::LineFailedDecode(e)),
        },

        None => return Err(KeyReadError::UnrecognizedFile),
    }
    match PublicKey::from_bytes(&buf[12..]) {
        Ok(key) => Ok(key),
        Err(e) => Err(KeyReadError::DeserError(e)),
    }
}

fn decode_pem_line(key_line: &str, buf: &mut [u8]) -> Result<usize, DecodeSliceError> {
    BASE64_STANDARD.decode_slice(key_line, buf)
}

pub fn init_sender_crypto(
    rng: &mut impl CryptoRng,
    sender_sk: PrivateKey,
    sender_pk: PublicKey,
    receiver_pk: &PublicKey,
) -> (EncappedKey, AeadCtxS<ChosenAead, ChosenKdf, ChosenKem>) {
    let opmode = OpModeS::Auth((sender_sk, sender_pk));
    hpke::setup_sender(&opmode, receiver_pk, PROTOCOL_INFO, rng).unwrap()
}

/// The only possible error variant is HpkeError::DecapError
pub fn try_decapsulate_key(
    sender_pk: PublicKey,
    receiver_sk: &PrivateKey,
    encapped_key: &EncappedKey,
) -> Option<AeadCtxR<ChosenAead, ChosenKdf, ChosenKem>> {
    let opmode = OpModeR::Auth(sender_pk);
    hpke::setup_receiver(&opmode, receiver_sk, encapped_key, PROTOCOL_INFO).ok()
}

#[cfg(test)]
mod tests {
    use crate::{PrivateKey, PublicKey, parse_pk, parse_sk};
    use hpke::{Deserializable, Serializable};

    #[test]
    fn pem_sk_decode() {
        let pem = "\
            -----BEGIN PRIVATE KEY-----\n\
            MC4CAQAwBQYDK2VuBCIEIHAKHLUz5njU6wgTxEX8vpKXr4bIBleXWUGhKfPhN15B\n\
            -----END PRIVATE KEY-----";
        let sk = parse_sk(pem).unwrap();
        let expected = PrivateKey::from_bytes(&[
            0x70, 0x0a, 0x1c, 0xb5, 0x33, 0xe6, 0x78, 0xd4, 0xeb, 0x08, 0x13, 0xc4, 0x45, 0xfc,
            0xbe, 0x92, 0x97, 0xaf, 0x86, 0xc8, 0x06, 0x57, 0x97, 0x59, 0x41, 0xa1, 0x29, 0xf3,
            0xe1, 0x37, 0x5e, 0x41,
        ])
        .unwrap();
        assert_eq!(expected.to_bytes(), sk.to_bytes());
    }

    #[test]
    fn pem_pk_decode() {
        let pem = "\
            -----BEGIN PUBLIC KEY-----\n\
            MCowBQYDK2VuAyEA/LYkVYQTh6+IM46ZEpdrf79Mgtr8mL1XZG8/niWghC8=\n\
            -----END PUBLIC KEY-----";
        let pk = parse_pk(pem).unwrap();
        let expected = PublicKey::from_bytes(&[
            0xfc, 0xb6, 0x24, 0x55, 0x84, 0x13, 0x87, 0xaf, 0x88, 0x33, 0x8e, 0x99, 0x12, 0x97,
            0x6b, 0x7f, 0xbf, 0x4c, 0x82, 0xda, 0xfc, 0x98, 0xbd, 0x57, 0x64, 0x6f, 0x3f, 0x9e,
            0x25, 0xa0, 0x84, 0x2f,
        ])
        .unwrap();
        assert_eq!(expected.to_bytes(), pk.to_bytes());
    }
}
