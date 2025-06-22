use crate::datatypes::ToBytes;
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Clone, Debug, PartialEq)]
pub struct Tlv {
    /// The Tag field is used to uniquely identify the particular optional parameter in question.
    pub tag: u16,

    /// The Length field indicates the length of the Value field in octets.
    /// Note that this length does not include the length of the Tag and Length fields.
    pub length: u16,

    /// The Value field contains the actual data for the optional parameter in question.
    pub value: Bytes,
}

impl ToBytes for Tlv {
    fn to_bytes(&self) -> Bytes {
        // the required size of the buffer if the length of the value plus 4
        // octets for the two u16s.
        let mut buffer = BytesMut::with_capacity(self.value.len() + 4);

        buffer.put_u16(self.tag);
        buffer.put_u16(self.length);
        buffer.put(self.value.chunk());

        buffer.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn tlv_to_bytes_basic() {
        let tlv = Tlv {
            tag: 0x0010,
            length: 4,
            value: Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]),
        };

        let bytes = tlv.to_bytes();

        let expected = vec![
            0x00, 0x10, // tag
            0x00, 0x04, // length
            0x01, 0x02, 0x03, 0x04, // value
        ];

        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn tlv_to_bytes_empty_value() {
        let tlv = Tlv {
            tag: 0x0204,
            length: 0,
            value: Bytes::new(),
        };

        let bytes = tlv.to_bytes();

        let expected = vec![
            0x02, 0x04, // tag
            0x00, 0x00, // length (0)
            // no value bytes
        ];

        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn tlv_to_bytes_single_byte_value() {
        let tlv = Tlv {
            tag: 0x020A,
            length: 1,
            value: Bytes::from_static(&[0xFF]),
        };

        let bytes = tlv.to_bytes();

        let expected = vec![
            0x02, 0x0A, // tag
            0x00, 0x01, // length
            0xFF, // value
        ];

        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn tlv_to_bytes_large_tag() {
        let tlv = Tlv {
            tag: 0xFFFF,
            length: 2,
            value: Bytes::from_static(&[0xAB, 0xCD]),
        };

        let bytes = tlv.to_bytes();

        let expected = vec![
            0xFF, 0xFF, // tag
            0x00, 0x02, // length
            0xAB, 0xCD, // value
        ];

        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn tlv_to_bytes_length_mismatch() {
        // Test case where length field doesn't match actual value length
        let tlv = Tlv {
            tag: 0x0010,
            length: 2, // Says 2 bytes
            value: Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]), // But has 4 bytes
        };

        let bytes = tlv.to_bytes();

        // Should serialize the length field as specified, not the actual value length
        let expected = vec![
            0x00, 0x10, // tag
            0x00, 0x02, // length (as specified, not actual)
            0x01, 0x02, 0x03, 0x04, // full value (regardless of length field)
        ];

        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn tlv_to_bytes_string_value() {
        let string_value = "Hello, SMPP!";
        let tlv = Tlv {
            tag: 0x001D,
            length: string_value.len() as u16,
            value: Bytes::from(string_value.as_bytes().to_vec()),
        };

        let bytes = tlv.to_bytes();

        // "Hello, SMPP!" is 12 bytes long
        let mut expected = vec![
            0x00, 0x1D, // tag
            0x00, 0x0C, // length (12 bytes)
        ];
        expected.extend_from_slice(string_value.as_bytes());

        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn tlv_roundtrip_consistency() {
        let original = Tlv {
            tag: 0x020A,
            length: 3,
            value: Bytes::from_static(&[0xAA, 0xBB, 0xCC]),
        };

        let serialized = original.to_bytes();
        
        // Manually parse it back (since we don't have a from_bytes method)
        assert_eq!(serialized.len(), 7); // 2 + 2 + 3
        assert_eq!(&serialized[0..2], &[0x02, 0x0A]); // tag
        assert_eq!(&serialized[2..4], &[0x00, 0x03]); // length
        assert_eq!(&serialized[4..7], &[0xAA, 0xBB, 0xCC]); // value
    }

    #[test]
    fn tlv_minimum_size() {
        let tlv = Tlv {
            tag: 0x0000,
            length: 0,
            value: Bytes::new(),
        };

        let bytes = tlv.to_bytes();

        // Minimum TLV is 4 bytes (2 for tag, 2 for length)
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes.as_ref(), &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn tlv_with_null_bytes_in_value() {
        let tlv = Tlv {
            tag: 0x0010,
            length: 5,
            value: Bytes::from_static(&[0x00, 0xFF, 0x00, 0xFF, 0x00]),
        };

        let bytes = tlv.to_bytes();

        let expected = vec![
            0x00, 0x10, // tag
            0x00, 0x05, // length
            0x00, 0xFF, 0x00, 0xFF, 0x00, // value with nulls
        ];

        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn tlv_max_length() {
        // Test with maximum possible length value
        let tlv = Tlv {
            tag: 0x0010,
            length: 0xFFFF,
            value: Bytes::from(vec![0x42; 65535]), // 65535 bytes of 0x42
        };

        let bytes = tlv.to_bytes();

        assert_eq!(bytes.len(), 4 + 65535); // header + value
        assert_eq!(&bytes[0..2], &[0x00, 0x10]); // tag
        assert_eq!(&bytes[2..4], &[0xFF, 0xFF]); // length
        assert_eq!(bytes[4], 0x42); // first value byte
        assert_eq!(bytes[bytes.len() - 1], 0x42); // last value byte
    }
}
