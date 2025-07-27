//! The purpose of the outbind operation is to allow the SMSC signal an ESME to
//! originate a bind_receiver request to the SMSC. An example of where such a
//! facility might be applicable would be where the SMSC had outstanding
//! messages for delivery to the ESME.
//!
//! An outbind SMPP session between an SMSC and an ESME can be initiated by the
//! SMSC first establishing a network connection with the ESME.
//!
//! Once a network connection has been established, the SMSC should bind to the
//! ESME by issuing an "outbind" request. The ESME should respond with a
//! "bind_receiver" request to which the SMSC will reply with a
//! "bind_receiver_resp".
//!
//! If the ESME does not accept the outbind session (e.g. because of an illegal
//! system_id or password etc.) the ESME should disconnect the network
//! connection.
//!
//! Once the SMPP session is established the characteristics of the session are
//! that of a normal SMPP receiver session.

use crate::codec::{CodecError, Decodable, Encodable, PduHeader};
use crate::datatypes::{CommandId, CommandStatus, Password, SystemId};
use bytes::{Buf, BufMut, BytesMut};
use std::io::Cursor;

#[derive(Clone, Debug, PartialEq)]
pub struct Outbind {
    // pub command_length: u32,
    // pub command_id: CommandId,
    /// Command status is unused for outbind and should always be 0
    pub command_status: CommandStatus,
    pub sequence_number: u32,
    /// 5.2.1: The system_id is used by the SMSC to determine the correct type
    ///        of ESME (i.e. transmitter, receiver or transceiver) and to
    ///        determine the functionality available to the ESME within the
    ///        SMSC.
    pub system_id: SystemId,

    /// The password used by the ESME to identify itself to the SMSC.
    pub password: Option<Password>,
}

#[derive(Debug, thiserror::Error)]
pub enum OutbindValidationError {
    #[error("Fixed array fields are always valid - this error should not occur")]
    FixedArrayError,
}

impl Outbind {
    /// Validates the Outbind PDU according to SMPP v3.4 specification
    /// Fixed array fields are always valid by construction
    pub fn validate(&self) -> Result<(), OutbindValidationError> {
        // Fixed-size arrays guarantee field length constraints are met
        Ok(())
    }
}

// New codec trait implementations

impl Decodable for Outbind {
    fn command_id() -> CommandId {
        CommandId::Outbind
    }

    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        // Validate header
        Self::validate_header(&header)?;

        // Parse system_id (variable length null-terminated string, max 16 chars)
        let system_id_str = Self::read_c_string(buf, 17, "system_id")?; // 16 + null
        let system_id = SystemId::from_parsed_string(system_id_str).map_err(|e| {
            CodecError::FieldValidation {
                field: "system_id",
                reason: e.to_string(),
            }
        })?;

        // Parse password (variable length null-terminated string, max 9 chars)
        let password_str = Self::read_c_string(buf, 10, "password")?; // 9 + null
        let password = if password_str.is_empty() {
            None
        } else {
            Some(Password::from_parsed_string(password_str).map_err(|e| {
                CodecError::FieldValidation {
                    field: "password",
                    reason: e.to_string(),
                }
            })?)
        };

        Ok(Outbind {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            system_id,
            password,
        })
    }
}

impl Outbind {
    /// Helper function to read null-terminated C strings with length limits
    fn read_c_string(
        buf: &mut Cursor<&[u8]>,
        max_len: usize,
        field_name: &'static str,
    ) -> Result<String, CodecError> {
        let mut string_bytes = Vec::new();
        let mut bytes_read = 0;

        while bytes_read < max_len {
            if buf.remaining() == 0 {
                return Err(CodecError::Incomplete);
            }

            let byte = buf.get_u8();
            bytes_read += 1;

            if byte == 0 {
                // Found null terminator
                break;
            }

            string_bytes.push(byte);
        }

        String::from_utf8(string_bytes).map_err(|e| CodecError::Utf8Error {
            field: field_name,
            source: e,
        })
    }
}

impl Encodable for Outbind {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Encode PDU header
        let header = PduHeader {
            command_length: 0, // Will be set by the caller
            command_id: CommandId::Outbind,
            command_status: self.command_status,
            sequence_number: self.sequence_number,
        };
        header.encode(buf)?;

        // Encode body - variable length null-terminated strings to match old format
        buf.extend_from_slice(self.system_id.as_ref());
        buf.put_u8(0); // null terminator

        if let Some(ref password) = self.password {
            buf.extend_from_slice(password.as_ref());
        }
        buf.put_u8(0); // null terminator for password (even if empty)

        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = PduHeader::SIZE;
        size += self.system_id.as_ref().len() + 1; // +1 for null terminator
        size += self.password.as_ref().map_or(0, |p| p.as_ref().len()) + 1; // +1 for null terminator
        size
    }
}

// Convenience constructors
impl Outbind {
    pub fn new(sequence_number: u32, system_id: SystemId, password: Option<Password>) -> Self {
        Self {
            command_status: CommandStatus::Ok,
            sequence_number,
            system_id,
            password,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbind_to_bytes() {
        let outbind = Outbind {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            system_id: "SMPP3TEST".parse::<SystemId>().unwrap(),
            password: Some("secret".parse::<Password>().unwrap()),
        };

        let expected = vec![
            0x00, 0x00, 0x00, 0x21, // length
            0x00, 0x00, 0x00, 0x0b, // command_id
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            0x53, 0x4d, 0x50, 0x50, // system_id
            0x33, 0x54, 0x45, 0x53, // system_id
            0x54, 0x00, // system_id
            0x73, 0x65, 0x63, 0x72, // password
            0x65, 0x74, 0x00, // password
        ];

        assert_eq!(&Encodable::to_bytes(&outbind), &expected);
    }

    #[test]
    fn outbind_to_bytes_no_password() {
        let outbind = Outbind {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            system_id: "SMPP3TEST".parse::<SystemId>().unwrap(),
            password: None,
        };

        let expected = vec![
            0x00, 0x00, 0x00, 0x1b, // length
            0x00, 0x00, 0x00, 0x0b, // command_id
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            0x53, 0x4d, 0x50, 0x50, // system_id
            0x33, 0x54, 0x45, 0x53, // system_id
            0x54, 0x00, // system_id
            0x00, // password
        ];
        assert_eq!(&Encodable::to_bytes(&outbind), &expected);
    }

    #[test]
    fn outbind_field_length_validation_system_id() {
        // Test that SystemId correctly rejects strings that are too long
        let long_system_id = "A".repeat(16); // Too long - max is 15
        let result = long_system_id.parse::<SystemId>();
        assert!(result.is_err());

        // Valid SystemId should work in Outbind
        let outbind = Outbind {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            system_id: "valid".parse::<SystemId>().unwrap(),
            password: Some("pass".parse::<Password>().unwrap()),
        };

        // Fixed arrays are always valid
        assert!(outbind.validate().is_ok());
    }

    #[test]
    fn outbind_field_length_validation_password() {
        // Test that Password correctly rejects strings that are too long
        let long_password = "A".repeat(9); // Too long - max is 8
        let result = long_password.parse::<Password>();
        assert!(result.is_err());

        // Valid Password should work in Outbind
        let outbind = Outbind {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            system_id: "TEST".parse::<SystemId>().unwrap(),
            password: Some("validpw".parse::<Password>().unwrap()),
        };

        // Fixed arrays are always valid
        assert!(outbind.validate().is_ok());
    }

    #[test]
    fn outbind_max_valid_lengths() {
        // Test that maximum valid lengths work correctly
        let outbind = Outbind {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            system_id: "A".repeat(15).parse::<SystemId>().unwrap(), // Max allowed
            password: Some("B".repeat(8).parse::<Password>().unwrap()), // Max allowed
        };

        let bytes = Encodable::to_bytes(&outbind);
        assert!(bytes.len() > 16); // Should serialize successfully
    }

    #[test]
    fn outbind_roundtrip_test() {
        use crate::frame::Frame;
        use std::io::Cursor;

        let original = Outbind {
            command_status: CommandStatus::Ok,
            sequence_number: 42,
            system_id: "SMPP3TEST".parse::<SystemId>().unwrap(),
            password: Some("secret08".parse::<Password>().unwrap()),
        };

        // Serialize to bytes
        let serialized = Encodable::to_bytes(&original);

        // Parse back from bytes
        let mut cursor = Cursor::new(serialized.as_ref());
        let parsed_frame = Frame::parse(&mut cursor).unwrap();

        // Verify it matches
        if let Frame::Outbind(parsed) = parsed_frame {
            assert_eq!(parsed.sequence_number, original.sequence_number);
            assert_eq!(parsed.system_id, original.system_id);
            assert_eq!(parsed.password, original.password);
        } else {
            panic!("Expected Outbind frame");
        }
    }
}
