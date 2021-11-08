use crate::datatypes::{CommandId, CommandStatus, ToBytes};
use bytes::{BufMut, Bytes, BytesMut};

/// The purpose of the SMPP unbind operation is to deregister an instance of an ESME from the SMSC
/// and inform the SMSC that the ESME no longer wishes to use this network connection for the
/// submission or delivery of messages.
///
/// Thus, the unbind operation may be viewed as a form of SMSC logoff request to close the current
/// SMPP session.
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
        let mut buffer = BytesMut::with_capacity(12);

        // Write junk data that we'll replace later with the actual length
        buffer.put_u32(0_u32);

        buffer.put_u32(CommandId::Unbind as u32);
        buffer.put_u32(self.command_status as u32);
        buffer.put_u32(self.sequence_number);

        // length should always be 12, but no harm in calculating it to avoid hard coding magic
        // values
        let length = buffer.len() as u32;

        let length_section = &mut buffer[0..][..4];
        length_section.copy_from_slice(&length.to_be_bytes());

        buffer.freeze()
    }
}

impl ToBytes for UnbindResponse {
    fn to_bytes(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(12);

        // Write junk data that we'll replace later with the actual length
        buffer.put_u32(0_u32);

        buffer.put_u32(CommandId::UnbindResp as u32);
        buffer.put_u32(self.command_status as u32);
        buffer.put_u32(self.sequence_number);

        // length should always be 12, but no harm in calculating it to avoid hard coding magic
        // values
        let length = buffer.len() as u32;

        let length_section = &mut buffer[0..][..4];
        length_section.copy_from_slice(&length.to_be_bytes());

        buffer.freeze()
    }
}
