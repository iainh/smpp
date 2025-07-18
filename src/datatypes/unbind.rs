use crate::datatypes::{CommandId, CommandStatus, ToBytes};
use bytes::{BufMut, Bytes, BytesMut};

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
