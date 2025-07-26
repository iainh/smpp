use crate::codec::{CodecError, Decodable, Encodable, PduHeader};
use crate::datatypes::{CommandId, CommandStatus, ToBytes};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;

/// The purpose of the SMPP unbind operation is to deregister an instance of an
/// ESME from the SMSC and inform the SMSC that the ESME no longer wishes to
/// use this network connection for the submission or delivery of messages.
///
/// Thus, the unbind operation may be viewed as a form of SMSC logoff request
/// to close the current SMPP session.
#[derive(Clone, Debug, PartialEq)]
pub struct Unbind {
    // pub command_length: u32,
    // pub command_id: CommandId::Unbind,
    pub command_status: CommandStatus,
    pub sequence_number: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UnbindResponse {
    // pub command_length: u32,
    // pub command_id: CommandId::UnbindResponse,
    pub command_status: CommandStatus,
    pub sequence_number: u32,
}

impl ToBytes for Unbind {
    fn to_bytes(&self) -> Bytes {
        let length = 16; // SMPP header is 16 bytes (4+4+4+4), unbind has no body
        let mut buffer = BytesMut::with_capacity(length);

        buffer.put_u32(length as u32);
        buffer.put_u32(CommandId::Unbind as u32);
        buffer.put_u32(0u32); // Request PDUs must have command_status = 0 per SMPP spec
        buffer.put_u32(self.sequence_number);
        buffer.freeze()
    }
}

impl ToBytes for UnbindResponse {
    fn to_bytes(&self) -> Bytes {
        let length = 16; // SMPP header is 16 bytes (4+4+4+4), unbind response has no body
        let mut buffer = BytesMut::with_capacity(length);

        buffer.put_u32(length as u32);
        buffer.put_u32(CommandId::UnbindResp as u32);
        buffer.put_u32(self.command_status as u32);
        buffer.put_u32(self.sequence_number);
        buffer.freeze()
    }
}

// New codec trait implementations

impl Decodable for Unbind {
    fn command_id() -> CommandId {
        CommandId::Unbind
    }

    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        // Validate header
        Self::validate_header(&header)?;

        // unbind has no body - just verify we're at the end
        if buf.has_remaining() {
            return Err(CodecError::FieldValidation {
                field: "unbind_body",
                reason: "unbind PDU should have no body".to_string(),
            });
        }

        Ok(Unbind {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
        })
    }
}

impl Encodable for Unbind {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Calculate total length (header only)
        let total_length = PduHeader::SIZE as u32;

        // Encode header
        let header = PduHeader {
            command_length: total_length,
            command_id: CommandId::Unbind,
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

impl Decodable for UnbindResponse {
    fn command_id() -> CommandId {
        CommandId::UnbindResp
    }

    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        // Validate header
        Self::validate_header(&header)?;

        // unbind_resp has no body
        if buf.has_remaining() {
            return Err(CodecError::FieldValidation {
                field: "unbind_resp_body",
                reason: "unbind_resp PDU should have no body".to_string(),
            });
        }

        Ok(UnbindResponse {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
        })
    }
}

impl Encodable for UnbindResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Calculate total length (header only)
        let total_length = PduHeader::SIZE as u32;

        // Encode header
        let header = PduHeader {
            command_length: total_length,
            command_id: CommandId::UnbindResp,
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

// Convenience constructors
impl Unbind {
    pub fn new(sequence_number: u32) -> Self {
        Self {
            command_status: CommandStatus::Ok,
            sequence_number,
        }
    }
}

impl UnbindResponse {
    pub fn new(sequence_number: u32) -> Self {
        Self {
            command_status: CommandStatus::Ok,
            sequence_number,
        }
    }

    pub fn error(sequence_number: u32, status: CommandStatus) -> Self {
        Self {
            command_status: status,
            sequence_number,
        }
    }
}
