use crate::codec::{CodecError, Decodable, Encodable, PduHeader};
use crate::datatypes::{CommandId, CommandStatus, ToBytes};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;

/// GenericNack is used to acknowledge the receipt of a PDU when the receiving
/// entity cannot process the PDU due to errors such as invalid command_id,
/// invalid command_status, or other format errors.
///
/// The generic_nack PDU has no message body and only contains the standard
/// SMPP header. It is typically sent in response to a malformed PDU where
/// the command_id cannot be determined or the PDU cannot be parsed correctly.
#[derive(Clone, Debug, PartialEq)]
pub struct GenericNack {
    // pub command_length: u32, (always 16 for generic_nack)
    // pub command_id: CommandId::GenericNack, (always 0x80000000)
    /// The command_status field indicates the reason for the generic_nack
    pub command_status: CommandStatus,
    /// The sequence_number from the original PDU that caused the error.
    /// If the original sequence_number cannot be determined, this should be 0.
    pub sequence_number: u32,
    // No body - generic_nack has no mandatory or optional parameters
}

impl GenericNack {
    /// Creates a new GenericNack with the specified command status and sequence number
    pub fn new(command_status: CommandStatus, sequence_number: u32) -> Self {
        Self {
            command_status,
            sequence_number,
        }
    }

    /// Creates a GenericNack for an invalid command ID error
    pub fn invalid_command_id(sequence_number: u32) -> Self {
        Self::new(CommandStatus::InvalidCommandId, sequence_number)
    }

    /// Creates a GenericNack for an invalid command length error
    pub fn invalid_command_length(sequence_number: u32) -> Self {
        Self::new(CommandStatus::InvalidCommandLength, sequence_number)
    }

    /// Creates a GenericNack for an invalid message length error  
    pub fn invalid_message_length(sequence_number: u32) -> Self {
        Self::new(CommandStatus::InvalidMsgLength, sequence_number)
    }

    /// Creates a GenericNack for a system error
    pub fn system_error(sequence_number: u32) -> Self {
        Self::new(CommandStatus::SystemError, sequence_number)
    }

    /// Creates a GenericNack when the sequence number cannot be determined from malformed PDU
    pub fn unknown_sequence() -> Self {
        Self::new(CommandStatus::InvalidCommandLength, 0)
    }
}

impl ToBytes for GenericNack {
    fn to_bytes(&self) -> Bytes {
        // Generic NACK always has a fixed length of 16 bytes (header only)
        const GENERIC_NACK_LENGTH: u32 = 16;

        let mut buffer = BytesMut::with_capacity(GENERIC_NACK_LENGTH as usize);

        // Standard SMPP header
        buffer.put_u32(GENERIC_NACK_LENGTH);
        buffer.put_u32(CommandId::GenericNack as u32);
        buffer.put_u32(self.command_status as u32);
        buffer.put_u32(self.sequence_number);

        // No body for generic_nack

        buffer.freeze()
    }
}

// New codec trait implementations

impl Decodable for GenericNack {
    fn command_id() -> CommandId {
        CommandId::GenericNack
    }

    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        // Validate header
        Self::validate_header(&header)?;

        // generic_nack has no body - just verify we're at the end
        if buf.has_remaining() {
            return Err(CodecError::FieldValidation {
                field: "generic_nack_body",
                reason: "generic_nack PDU should have no body".to_string(),
            });
        }

        Ok(GenericNack {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
        })
    }
}

impl Encodable for GenericNack {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Calculate total length (header only)
        let total_length = PduHeader::SIZE as u32;

        // Encode header
        let header = PduHeader {
            command_length: total_length,
            command_id: CommandId::GenericNack,
            command_status: self.command_status,
            sequence_number: self.sequence_number,
        };
        header.encode(buf)?;

        // No body to encode
        Ok(())
    }

    fn encoded_size(&self) -> usize {
        PduHeader::SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_nack_to_bytes() {
        let generic_nack = GenericNack {
            command_status: CommandStatus::InvalidCommandId,
            sequence_number: 42,
        };

        let bytes = ToBytes::to_bytes(&generic_nack);

        let expected = vec![
            0x00, 0x00, 0x00, 0x10, // command_length (16)
            0x80, 0x00, 0x00, 0x00, // command_id (GenericNack = 0x80000000)
            0x00, 0x00, 0x00, 0x03, // command_status (InvalidCommandId = 3)
            0x00, 0x00, 0x00, 0x2A, // sequence_number (42)
        ];

        assert_eq!(&bytes, &expected);
        assert_eq!(bytes.len(), 16); // Always 16 bytes
    }

    #[test]
    fn generic_nack_convenience_constructors() {
        let nack = GenericNack::invalid_command_id(123);
        assert_eq!(nack.command_status, CommandStatus::InvalidCommandId);
        assert_eq!(nack.sequence_number, 123);

        let nack = GenericNack::invalid_command_length(456);
        assert_eq!(nack.command_status, CommandStatus::InvalidCommandLength);
        assert_eq!(nack.sequence_number, 456);

        let nack = GenericNack::invalid_message_length(789);
        assert_eq!(nack.command_status, CommandStatus::InvalidMsgLength);
        assert_eq!(nack.sequence_number, 789);

        let nack = GenericNack::system_error(999);
        assert_eq!(nack.command_status, CommandStatus::SystemError);
        assert_eq!(nack.sequence_number, 999);

        let nack = GenericNack::unknown_sequence();
        assert_eq!(nack.command_status, CommandStatus::InvalidCommandLength);
        assert_eq!(nack.sequence_number, 0);
    }

    #[test]
    fn generic_nack_fixed_length() {
        // Generic NACK should always be exactly 16 bytes regardless of content
        let test_cases = vec![
            GenericNack::new(CommandStatus::Ok, 0),
            GenericNack::new(CommandStatus::InvalidCommandId, u32::MAX),
            GenericNack::new(CommandStatus::SystemError, 12345),
        ];

        for nack in test_cases {
            let bytes = ToBytes::to_bytes(&nack);
            assert_eq!(bytes.len(), 16, "GenericNack should always be 16 bytes");
        }
    }

    #[test]
    fn generic_nack_roundtrip_test() {
        use crate::frame::Frame;
        use std::io::Cursor;

        let original = GenericNack {
            command_status: CommandStatus::InvalidCommandId,
            sequence_number: 9876,
        };

        // Serialize to bytes
        let serialized = ToBytes::to_bytes(&original);

        // Parse back from bytes
        let mut cursor = Cursor::new(serialized.as_ref());
        let parsed_frame = Frame::parse(&mut cursor).unwrap();

        // Verify it matches
        if let Frame::GenericNack(parsed) = parsed_frame {
            assert_eq!(parsed.command_status, original.command_status);
            assert_eq!(parsed.sequence_number, original.sequence_number);
        } else {
            panic!("Expected GenericNack frame");
        }
    }
}
