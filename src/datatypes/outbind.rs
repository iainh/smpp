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

use crate::datatypes::{CommandId, ToBytes, MAX_PASSWORD_LENGTH, MAX_SYSTEM_ID_LENGTH};
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
    pub system_id: String,

    /// The password used by the ESME to identify itself to the SMSC.
    pub password: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum OutbindValidationError {
    #[error("system_id exceeds maximum length of {MAX_SYSTEM_ID_LENGTH} characters ({} with null terminator): {actual}", MAX_SYSTEM_ID_LENGTH + 1)]
    SystemIdTooLong { actual: usize },

    #[error("password exceeds maximum length of {MAX_PASSWORD_LENGTH} characters ({} with null terminator): {actual}", MAX_PASSWORD_LENGTH + 1)]
    PasswordTooLong { actual: usize },
}

impl Outbind {
    /// Validates the Outbind PDU according to SMPP v3.4 specification
    pub fn validate(&self) -> Result<(), OutbindValidationError> {
        // Validate field length constraints
        if self.system_id.len() > MAX_SYSTEM_ID_LENGTH {
            return Err(OutbindValidationError::SystemIdTooLong {
                actual: self.system_id.len(),
            });
        }

        if let Some(ref password) = self.password {
            if password.len() > MAX_PASSWORD_LENGTH {
                return Err(OutbindValidationError::PasswordTooLong {
                    actual: password.len(),
                });
            }
        }

        Ok(())
    }
}

impl ToBytes for Outbind {
    fn to_bytes(&self) -> Bytes {
        // Validate field constraints per SMPP v3.4 specification
        self.validate().expect("Outbind validation failed");
        let mut buffer = BytesMut::with_capacity(1024);
        // Write junk data that we'll replace later with the actual length
        buffer.put_u32(0);

        buffer.put_u32(CommandId::Outbind as u32);
        // Command status is always 0 for outbind
        buffer.put_u32(b'\0' as u32);

        buffer.put_u32(self.sequence_number);

        buffer.put(self.system_id.as_bytes());
        buffer.put_u8(b'\0');

        if let Some(password) = &self.password {
            buffer.put(password.as_bytes());
        }

        buffer.put_u8(b'\0');

        let length = buffer.len() as u32;

        let length_section = &mut buffer[0..][..4];
        length_section.copy_from_slice(&length.to_be_bytes());

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
            system_id: "SMPP3TEST".to_string(),
            password: Some("secret".to_string()),
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
            system_id: "SMPP3TEST".to_string(),
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
        let outbind = Outbind {
            sequence_number: 1,
            system_id: "A".repeat(16), // Too long - max is 15
            password: Some("pass".to_string()),
        };

        // Validate should return an error for system_id too long
        let validation_result = outbind.validate();
        assert!(validation_result.is_err());
        assert!(matches!(
            validation_result.unwrap_err(),
            OutbindValidationError::SystemIdTooLong { .. }
        ));
    }

    #[test]
    fn outbind_field_length_validation_password() {
        let outbind = Outbind {
            sequence_number: 1,
            system_id: "TEST".to_string(),
            password: Some("A".repeat(9)), // Too long - max is 8
        };

        // Validate should return an error for password too long
        let validation_result = outbind.validate();
        assert!(validation_result.is_err());
        assert!(matches!(
            validation_result.unwrap_err(),
            OutbindValidationError::PasswordTooLong { .. }
        ));
    }

    #[test]
    fn outbind_max_valid_lengths() {
        // Test that maximum valid lengths work correctly
        let outbind = Outbind {
            sequence_number: 1,
            system_id: "A".repeat(15),     // Max allowed
            password: Some("B".repeat(8)), // Max allowed
        };

        let bytes = outbind.to_bytes();
        assert!(bytes.len() > 16); // Should serialize successfully
    }
}
