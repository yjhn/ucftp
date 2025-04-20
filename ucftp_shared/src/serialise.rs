pub const SER_BYTE_MAX: u8 = 247;

pub trait BufSerialise {
    /// Write serialized version of the value to buf. Returns number of bytes written.
    fn serialise_to_buf(self, buf: &mut Vec<u8>);
}

pub trait BufDeserialise {
    /// Deserialize value from buf. Returns (number of bytes read from buf, deserialized value).
    fn deserialise_from_buf(buf: &[u8]) -> (usize, Self);
}

impl BufSerialise for u64 {
    /// Serialise int to a representation that favors small numbers:
    /// - if 0 <= int < 248, result is int
    /// - if int > 247, the first encoded byte is 247 + <number of bytes used by int>,
    ///   which is then followed by int bytes in little-endian order
    fn serialise_to_buf(self, buf: &mut Vec<u8>) {
        let bytes = self.to_le_bytes();
        if self <= SER_BYTE_MAX as u64 {
            buf.push(bytes[0]);
            return;
        }

        // Calculate number of bytes used to represent a number
        let used_bytes = self.ilog2() / 8 + 1;

        buf.push(SER_BYTE_MAX + used_bytes as u8);
        buf.extend_from_slice(&bytes[..used_bytes as usize]);
    }
}

impl BufDeserialise for u64 {
    fn deserialise_from_buf(buf: &[u8]) -> (usize, u64) {
        let fb = buf[0];
        if fb < 248 {
            return (1, fb as u64);
        }

        let used_bytes = (fb - 247) as usize;
        let mut int = [0; 8];
        int[..used_bytes].copy_from_slice(&buf[1..=used_bytes]);
        (used_bytes + 1, u64::from_le_bytes(int))
    }
}

impl BufSerialise for &[u8] {
    fn serialise_to_buf(self, buf: &mut Vec<u8>) {
        (self.len() as u64).serialise_to_buf(buf);
        buf.extend_from_slice(self);
    }
}

impl BufDeserialise for Vec<u8> {
    fn deserialise_from_buf(buf: &[u8]) -> (usize, Self) {
        let (len_len, len) = u64::deserialise_from_buf(buf);
        let v = Vec::from(&buf[len_len..len_len + len as usize]);
        (len_len + len as usize, v)
    }
}

impl BufSerialise for &str {
    fn serialise_to_buf(self, buf: &mut Vec<u8>) {
        self.as_bytes().serialise_to_buf(buf)
    }
}

impl BufDeserialise for String {
    fn deserialise_from_buf(buf: &[u8]) -> (usize, Self) {
        let (l, v) = Vec::deserialise_from_buf(buf);
        let string = String::from_utf8(v).unwrap();
        (l, string)
    }
}

impl BufSerialise for &[String] {
    fn serialise_to_buf(self, buf: &mut Vec<u8>) {
        (self.len() as u64).serialise_to_buf(buf);
        for s in self {
            s.serialise_to_buf(buf);
        }
    }
}

impl BufSerialise for &[(String, String)] {
    fn serialise_to_buf(self, buf: &mut Vec<u8>) {
        (self.len() as u64).serialise_to_buf(buf);
        for (k, v) in self {
            k.serialise_to_buf(buf);
            v.serialise_to_buf(buf);
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
    use crate::serialise::{BufDeserialise, BufSerialise};

    fn serde<S: BufSerialise, D: BufDeserialise>(val: S) -> D {
        let mut buf = Vec::with_capacity(1000);
        val.serialise_to_buf(&mut buf);
        <D as BufDeserialise>::deserialise_from_buf(&buf).1
    }

    #[test]
    fn test_int_ser() {
        assert_eq!(0u64, serde(0));
        assert_eq!(1u64, serde(1));
        assert_eq!(12u64, serde(12));
        assert_eq!(123u64, serde(123));
        assert_eq!(1234u64, serde(1234));
        assert_eq!(12345u64, serde(12345));
        assert_eq!(123456u64, serde(123456));
        assert_eq!(1234567u64, serde(1234567));
        assert_eq!(12345678u64, serde(12345678));
        assert_eq!(123456789u64, serde(123456789));
        assert_eq!(1234567890u64, serde(1234567890));
        assert_eq!(12345678901u64, serde(12345678901));
        assert_eq!(123456789012u64, serde(123456789012));
        assert_eq!(1234567890123u64, serde(1234567890123));
        assert_eq!(12345678901234u64, serde(12345678901234));
        assert_eq!(123456789012345u64, serde(123456789012345));
    }

    #[test]
    fn test_str_ser() {
        assert_eq!("", serde::<_, String>(""));
        assert_eq!("a", serde::<_, String>("a"));
        assert_eq!("qwertyuiop", serde::<_, String>("qwertyuiop"));
        let s = "a".repeat(100_000);
        assert_eq!(s, serde::<_, String>(s.as_str()));
    }
}
