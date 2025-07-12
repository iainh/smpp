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

use crate::datatypes::{CommandId, ToBytes, SystemId, Password};
use bytes::{BufMut, Bytes, BytesMut};

#[derive(Clone, Debug, PartialEq)]
pub struct Outbind {
    // pub command_length: u32,
    // pub command_id: CommandId,
    /// Command status is unsed for outbind and should always be 0
    //pub command_status: CommandStatus,
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

impl ToBytes for Outbind {
    fn to_bytes(&self) -> Bytes {
        // Fixed arrays are always valid by construction
        self.validate().expect("Outbind validation failed");
        
        let system_id = self.system_id.as_ref();
        let password = self.password.as_ref().map(|p| p.as_ref());
        
        let length = 16 + system_id.len() + 1 + password.map_or(0, |p| p.len()) + 1;
        
        let mut buffer = BytesMut::with_capacity(length);
        
        buffer.put_u32(length as u32);
        buffer.put_u32(CommandId::Outbind as u32);
        // Command status is always 0 for outbind
        buffer.put_u32(0u32);
        buffer.put_u32(self.sequence_number);

        buffer.put(system_id);
        buffer.put_u8(b'\0');

        if let Some(password) = password {
            buffer.put(password);
        }

        buffer.put_u8(b'\0');

        buffer.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbind_to_bytes() {
        let outbind = Outbind {
            sequence_number: 1,
            system_id: SystemId::from_str("SMPP3TEST").unwrap(),
            password: Some(Password::from_str("secret").unwrap()),
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

        assert_eq!(&outbind.to_bytes(), &expected);
    }

    #[test]
    fn outbind_to_bytes_no_password() {
        let outbind = Outbind {
            sequence_number: 1,
            system_id: SystemId::from_str("SMPP3TEST").unwrap(),
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
        assert_eq!(&outbind.to_bytes(), &expected);
    }

    #[test]
    fn outbind_field_length_validation_system_id() {
        // Test that SystemId correctly rejects strings that are too long
        let long_system_id = "A".repeat(16); // Too long - max is 15
        let result = SystemId::from_str(&long_system_id);
        assert!(result.is_err());
        
        // Valid SystemId should work in Outbind
        let outbind = Outbind {
            sequence_number: 1,
            system_id: SystemId::from_str("valid").unwrap(),
            password: Some(Password::from_str("pass").unwrap()),
        };
        
        // Fixed arrays are always valid
        assert!(outbind.validate().is_ok());
    }

    #[test]
    fn outbind_field_length_validation_password() {
        // Test that Password correctly rejects strings that are too long
        let long_password = "A".repeat(9); // Too long - max is 8
        let result = Password::from_str(&long_password);
        assert!(result.is_err());
        
        // Valid Password should work in Outbind
        let outbind = Outbind {
            sequence_number: 1,
            system_id: SystemId::from_str("TEST").unwrap(),
            password: Some(Password::from_str("validpw").unwrap()),
        };
        
        // Fixed arrays are always valid
        assert!(outbind.validate().is_ok());
    }

    #[test]
    fn outbind_max_valid_lengths() {
        // Test that maximum valid lengths work correctly
        let outbind = Outbind {
            sequence_number: 1,
            system_id: SystemId::from_str(&"A".repeat(15)).unwrap(),     // Max allowed
            password: Some(Password::from_str(&"B".repeat(8)).unwrap()), // Max allowed
        };

        let bytes = outbind.to_bytes();
        assert!(bytes.len() > 16); // Should serialize successfully
    }

    #[test]
    fn outbind_roundtrip_test() {
        use crate::frame::Frame;
        use std::io::Cursor;

        let original = Outbind {
            sequence_number: 42,
            system_id: SystemId::from_str("SMPP3TEST").unwrap(),
            password: Some(Password::from_str("secret08").unwrap()),
        };

        // Serialize to bytes
        let serialized = original.to_bytes();

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
