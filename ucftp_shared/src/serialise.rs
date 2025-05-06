use std::str;

pub const U64_SER_BYTE_MAX: u8 = 248;
pub const U32_SER_BYTE_MAX: u8 = 252;

pub trait BufSerialize {
    /// Write serialized version of the value to buf. Returns number of bytes written.
    fn serialize_to_buf(self, buf: &mut Vec<u8>);
}

pub trait BufDeserialize {
    /// Deserialize value from buf. Returns (number of bytes read from buf, deserialized value).
    fn deserialize_from_buf(buf: &[u8]) -> (usize, Self);
}

impl BufSerialize for u64 {
    /// Serialise int to a representation that favors small numbers:
    /// - if 0 <= int <= U64_SER_BYTE_MAX, result is int
    /// - if int > U64_SER_BYTE_MAX, the first encoded byte is U64_SER_BYTE_MAX + <number of bytes used by int> - 1,
    ///   which is then followed by int bytes in little-endian order
    fn serialize_to_buf(self, buf: &mut Vec<u8>) {
        let bytes = self.to_le_bytes();
        if self <= U64_SER_BYTE_MAX as u64 {
            buf.push(bytes[0]);
            return;
        } else if self <= 255 {
            // U64_SER_BYTE_MAX < self <= 255 is encoded as u16
            buf.push(U64_SER_BYTE_MAX + 1);
            buf.push(bytes[0]);
            buf.push(0);
            return;
        }

        // Calculate number of bytes used to represent a number - 1
        let used_bytes = self.ilog2() / 8;

        buf.push(U64_SER_BYTE_MAX + used_bytes as u8);
        buf.extend_from_slice(&bytes[..used_bytes as usize + 1]);
    }
}

impl BufDeserialize for u64 {
    fn deserialize_from_buf(buf: &[u8]) -> (usize, u64) {
        let fb = buf[0];
        if fb <= U64_SER_BYTE_MAX {
            return (1, fb as u64);
        }

        let used_bytes = u64_used_bytes(fb);
        let mut int = [0; 8];
        int[..used_bytes].copy_from_slice(&buf[1..=used_bytes]);
        (used_bytes + 1, u64::from_le_bytes(int))
    }
}

impl BufSerialize for u32 {
    /// Serialise int to a representation that favors small numbers:
    /// - if 0 <= int <= U32_SER_BYTE_MAX, result is int
    /// - if int > U32_SER_BYTE_MAX, the first encoded byte is U32_SER_BYTE_MAX + <number of bytes used by int> - 1,
    ///   which is then followed by int bytes in little-endian order
    fn serialize_to_buf(self, buf: &mut Vec<u8>) {
        let bytes = self.to_le_bytes();
        if self <= U32_SER_BYTE_MAX as u32 {
            buf.push(bytes[0]);
            return;
        } else if self <= 255 {
            // U32_SER_BYTE_MAX < self <= 255 is encoded as u16
            buf.push(U32_SER_BYTE_MAX + 1);
            buf.push(bytes[0]);
            buf.push(0);
            return;
        }

        // Calculate number of bytes used to represent a number - 1
        let used_bytes = self.ilog2() / 8;

        buf.push(U32_SER_BYTE_MAX + used_bytes as u8);
        buf.extend_from_slice(&bytes[..used_bytes as usize + 1]);
    }
}

impl BufDeserialize for u32 {
    fn deserialize_from_buf(buf: &[u8]) -> (usize, u32) {
        let fb = buf[0];
        if fb <= U32_SER_BYTE_MAX {
            return (1, fb as u32);
        }

        let used_bytes = u32_used_bytes(fb);
        let mut int = [0; 4];
        int[..used_bytes].copy_from_slice(&buf[1..=used_bytes]);
        (used_bytes + 1, u32::from_le_bytes(int))
    }
}

impl BufSerialize for &[u8] {
    fn serialize_to_buf(self, buf: &mut Vec<u8>) {
        (self.len() as u64).serialize_to_buf(buf);
        buf.extend_from_slice(self);
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DeserializationError {
    /// Numeric value is expected at the current position but not present
    ValueExpected,
    /// Same meaning as ValueExpected, but used for total command length only
    CommandLenExpected,
    /// The supplied buffer is 0 bytes in length
    BufferEmpty,
    /// Incomplete numeric value
    IncompleteValue,
    /// When indicated buffer length is longer than actual buffer
    BufferTooShort,
    /// Bad encoding, e.g. for UTF-8 strings
    BadEncding,
    /// Command length does not match the one indicated in total length
    LengthMismatch,
    /// Unknown command type
    UnknownType,
    /// Some field has an unexpected value, e.g. a u32 field has value > u32::MAX
    BadFieldValue,
    /// Some enum has an unknown value
    UnknownEnumValue,
}

pub trait TryBufDeserialize
where
    Self: Sized,
{
    /// Deserialize value from buf. Returns (number of bytes read from buf, deserialized value).
    fn try_deserialize_from_buf(buf: &[u8]) -> Result<(usize, Self), DeserializationError>;
}

/// How many bytes is the actual number using
fn u64_used_bytes(first_byte: u8) -> usize {
    (first_byte - U64_SER_BYTE_MAX) as usize + 1
}

fn u32_used_bytes(first_byte: u8) -> usize {
    (first_byte - U32_SER_BYTE_MAX) as usize + 1
}

impl TryBufDeserialize for u64 {
    fn try_deserialize_from_buf(buf: &[u8]) -> Result<(usize, u64), DeserializationError> {
        if buf.is_empty() {
            return Err(DeserializationError::ValueExpected);
        }
        let fb = buf[0];
        if fb <= U64_SER_BYTE_MAX {
            return Ok((1, fb as u64));
        }

        let used_bytes = u64_used_bytes(fb);
        if buf.len() < used_bytes + 1 {
            return Err(DeserializationError::IncompleteValue);
        }
        let mut int = [0; 8];
        int[..used_bytes].copy_from_slice(&buf[1..=used_bytes]);
        Ok((used_bytes + 1, u64::from_le_bytes(int)))
    }
}

impl TryBufDeserialize for u32 {
    fn try_deserialize_from_buf(buf: &[u8]) -> Result<(usize, u32), DeserializationError> {
        if buf.is_empty() {
            return Err(DeserializationError::ValueExpected);
        }
        let fb = buf[0];
        if fb <= U32_SER_BYTE_MAX {
            return Ok((1, fb as u32));
        }

        let used_bytes = u32_used_bytes(fb);
        if buf.len() < used_bytes + 1 {
            return Err(DeserializationError::IncompleteValue);
        }
        let mut int = [0; 4];
        int[..used_bytes].copy_from_slice(&buf[1..=used_bytes]);
        Ok((used_bytes + 1, u32::from_le_bytes(int)))
    }
}

impl TryBufDeserialize for Box<[u8]> {
    fn try_deserialize_from_buf(buf: &[u8]) -> Result<(usize, Self), DeserializationError> {
        let (used, len) = u64::try_deserialize_from_buf(buf)?;
        if buf.len() < used + len as usize {
            return Err(DeserializationError::BufferTooShort);
        }
        let v = buf[used..used + len as usize].into();
        Ok((used + len as usize, v))
    }
}

impl BufSerialize for &str {
    fn serialize_to_buf(self, buf: &mut Vec<u8>) {
        self.as_bytes().serialize_to_buf(buf)
    }
}

impl TryBufDeserialize for Box<str> {
    fn try_deserialize_from_buf(buf: &[u8]) -> Result<(usize, Self), DeserializationError> {
        let (l, v) = Box::try_deserialize_from_buf(buf)?;
        let string = match str::from_utf8(&v) {
            Ok(s) => s.into(),
            Err(_) => return Err(DeserializationError::BadEncding),
        };
        Ok((l, string))
    }
}

impl TryBufDeserialize for Box<[(Box<str>, Box<str>)]> {
    fn try_deserialize_from_buf(buf: &[u8]) -> Result<(usize, Self), DeserializationError> {
        let (mut buf_used, len) = u64::try_deserialize_from_buf(buf)?;
        // We cannot check for buffer length here, as it depends on strings' length
        let mut res = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let (used, key) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
            buf_used += used;
            let (used, val) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
            buf_used += used;
            res.push((key, val));
        }
        Ok((buf_used, res.into()))
    }
}

impl TryBufDeserialize for Box<[Box<str>]> {
    fn try_deserialize_from_buf(buf: &[u8]) -> Result<(usize, Self), DeserializationError> {
        let (mut buf_used, len) = u64::try_deserialize_from_buf(buf)?;
        // We cannot check for buffer length here, as it depends on strings' length
        let mut res = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let (used, val) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
            buf_used += used;
            res.push(val);
        }
        Ok((buf_used, res.into()))
    }
}

impl BufSerialize for &[String] {
    fn serialize_to_buf(self, buf: &mut Vec<u8>) {
        (self.len() as u64).serialize_to_buf(buf);
        for s in self {
            s.serialize_to_buf(buf);
        }
    }
}

impl BufSerialize for &[(String, String)] {
    fn serialize_to_buf(self, buf: &mut Vec<u8>) {
        (self.len() as u64).serialize_to_buf(buf);
        for (k, v) in self {
            k.serialize_to_buf(buf);
            v.serialize_to_buf(buf);
        }
    }
}

/// Append little-endian bytes of val to buf
pub fn dump_le(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Extract val from first 8 bytes of buf
pub fn u64_from_le_bytes(buf: &[u8]) -> u64 {
    let arr = *buf.first_chunk::<8>().unwrap();
    u64::from_le_bytes(arr)
}

/// Extract val from first 4 bytes of buf
pub fn u32_from_le_bytes(buf: &[u8]) -> u32 {
    let arr = *buf.first_chunk::<4>().unwrap();
    u32::from_le_bytes(arr)
}

/// Extracts 6 little-endian bytes from buffer
pub fn seq_deser(buf: &[u8]) -> u64 {
    let mut arr = [0; 8];
    arr[0] = buf[0];
    arr[1] = buf[1];
    arr[2] = buf[2];
    arr[3] = buf[3];
    arr[4] = buf[4];
    arr[5] = buf[5];
    arr[6] = 0;
    arr[7] = 0;
    u64::from_le_bytes(arr)
}

#[cfg(test)]
mod tests {
    use std::ops::BitAnd;

    use crate::serialise::{BufDeserialize, BufSerialize};

    use super::TryBufDeserialize;

    fn serde<S: BufSerialize, D: BufDeserialize + TryBufDeserialize + BitAnd<D, Output = D>>(
        val: S,
    ) -> D {
        let mut buf = Vec::with_capacity(1000);
        val.serialize_to_buf(&mut buf);
        let v1 = <D as BufDeserialize>::deserialize_from_buf(&buf).1;
        let v2 = <D as TryBufDeserialize>::try_deserialize_from_buf(&buf)
            .unwrap()
            .1;
        // If they are not the same, result will be wrong
        v1 & v2
    }

    #[test]
    fn test_int_ser_u64() {
        assert_eq!(0u64, serde(0u64));
        assert_eq!(1u64, serde(1u64));
        assert_eq!(12u64, serde(12u64));
        assert_eq!(123u64, serde(123u64));
        assert_eq!(255u64, serde(255u64));
        assert_eq!(1234u64, serde(1234u64));
        assert_eq!(12345u64, serde(12345u64));
        assert_eq!(123456u64, serde(123456u64));
        assert_eq!(1234567u64, serde(1234567u64));
        assert_eq!(12345678u64, serde(12345678u64));
        assert_eq!(123456789u64, serde(123456789u64));
        assert_eq!(1234567890u64, serde(1234567890u64));
        assert_eq!(12345678901u64, serde(12345678901u64));
        assert_eq!(123456789012u64, serde(123456789012u64));
        assert_eq!(1234567890123u64, serde(1234567890123u64));
        assert_eq!(12345678901234u64, serde(12345678901234u64));
        assert_eq!(123456789012345u64, serde(123456789012345u64));
    }

    #[test]
    fn test_int_ser_u32() {
        assert_eq!(0u32, serde(0u32));
        assert_eq!(1u32, serde(1u32));
        assert_eq!(12u32, serde(12u32));
        assert_eq!(123u32, serde(123u32));
        assert_eq!(255u32, serde(255u32));
        assert_eq!(1234u32, serde(1234u32));
        assert_eq!(12345u32, serde(12345u32));
        assert_eq!(123456u32, serde(123456u32));
        assert_eq!(1234567u32, serde(1234567u32));
        assert_eq!(12345678u32, serde(12345678u32));
        assert_eq!(123456789u32, serde(123456789u32));
        assert_eq!(1234567890u32, serde(1234567890u32));
    }

    fn serde_str(val: &str) -> Box<str> {
        let mut buf = Vec::with_capacity(1000);
        val.serialize_to_buf(&mut buf);
        Box::try_deserialize_from_buf(&buf).unwrap().1
    }

    #[test]
    fn test_str_ser() {
        assert_eq!("", serde_str("").as_ref());
        assert_eq!("a", serde_str("a").as_ref());
        assert_eq!("qwertyuiop", serde_str("qwertyuiop").as_ref());
        let s = "a".repeat(100_000);
        assert_eq!(s, serde_str(s.as_str()).as_ref());
    }
}
