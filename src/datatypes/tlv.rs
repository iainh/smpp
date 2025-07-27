use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;

// Import codec traits
use crate::codec::{CodecError, Encodable};

// Standard TLV tag constants per SMPP v3.4 specification
pub mod tags {
    pub const USER_MESSAGE_REFERENCE: u16 = 0x0204;
    pub const SOURCE_PORT: u16 = 0x020A;
    pub const SOURCE_ADDR_SUBMIT: u16 = 0x020B;
    pub const DESTINATION_PORT: u16 = 0x020C;
    pub const DEST_ADDR_SUBMIT: u16 = 0x020D;
    pub const SAR_MSG_REF_NUM: u16 = 0x020E;
    pub const SAR_TOTAL_SEGMENTS: u16 = 0x020F;
    pub const SAR_SEGMENT_SEQNUM: u16 = 0x0210;
    pub const MORE_MESSAGES_TO_SEND: u16 = 0x0426;
    pub const PAYLOAD_TYPE: u16 = 0x0019;
    pub const MESSAGE_PAYLOAD: u16 = 0x0424;
    pub const PRIVACY_INDICATOR: u16 = 0x0201;
    pub const CALLBACK_NUM: u16 = 0x0381;
    pub const CALLBACK_NUM_PRES_IND: u16 = 0x0302;
    pub const CALLBACK_NUM_ATAG: u16 = 0x0303;
    pub const SOURCE_SUBADDRESS: u16 = 0x0202;
    pub const DEST_SUBADDRESS: u16 = 0x0203;
    pub const DISPLAY_TIME: u16 = 0x1201;
    pub const SMS_SIGNAL: u16 = 0x1203;
    pub const MS_VALIDITY: u16 = 0x1204;
    pub const MS_MSG_WAIT_FACILITIES: u16 = 0x1205;
    pub const NUMBER_OF_MESSAGES: u16 = 0x0205;
    pub const ALERT_ON_MSG_DELIVERY: u16 = 0x130C;
    pub const LANGUAGE_INDICATOR: u16 = 0x000D;
    pub const ITS_REPLY_TYPE: u16 = 0x1380;
    pub const ITS_SESSION_INFO: u16 = 0x1383;
    pub const USSD_SERVICE_OP: u16 = 0x0501;

    // SMPP v5.0 TLV tags
    pub const CONGESTION_STATE: u16 = 0x142C;
    pub const BILLING_IDENTIFICATION: u16 = 0x0600;
    pub const SOURCE_NETWORK_ID: u16 = 0x060E;
    pub const DEST_NETWORK_ID: u16 = 0x060F;
    pub const SOURCE_NODE_ID: u16 = 0x060C;
    pub const DEST_NODE_ID: u16 = 0x060D;

    // Additional TLV tags for deliver_sm and other PDUs
    pub const USER_DATA_HEADER: u16 = 0x0005;
    pub const NETWORK_ERROR_CODE: u16 = 0x0423;
    pub const DELIVERY_FAILURE_REASON: u16 = 0x0425;
    pub const ADDITIONAL_STATUS_INFO_TEXT: u16 = 0x001D;
    pub const DPF_RESULT: u16 = 0x0420;
    pub const SET_DPF: u16 = 0x0421;
    pub const MS_AVAILABILITY_STATUS: u16 = 0x0422;
    pub const RECEIPTED_MESSAGE_ID: u16 = 0x001E;
    pub const MESSAGE_STATE: u16 = 0x0427;
}

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

// Codec trait implementations for TLV
impl Encodable for Tlv {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        buf.put_u16(self.tag);
        buf.put_u16(self.length);
        buf.extend_from_slice(&self.value);
        Ok(())
    }

    fn encoded_size(&self) -> usize {
        4 + self.value.len() // 2 bytes tag + 2 bytes length + value
    }
}

impl Tlv {
    /// Convert TLV to bytes without PDU header (overrides Encodable::to_bytes)
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        self.encode(&mut buf).expect("TLV encoding should not fail");
        buf.freeze()
    }

    /// Decode a TLV from the buffer
    pub fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        if buf.remaining() < 4 {
            return Err(CodecError::Incomplete);
        }

        let tag = buf.get_u16();
        let length = buf.get_u16();

        if buf.remaining() < length as usize {
            return Err(CodecError::Incomplete);
        }

        let mut value_bytes = vec![0u8; length as usize];
        buf.copy_to_slice(&mut value_bytes);
        let value = Bytes::from(value_bytes);

        Ok(Self { tag, length, value })
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
            length: 2,                                            // Says 2 bytes
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
            value: Bytes::copy_from_slice(string_value.as_bytes()),
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
