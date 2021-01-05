use crate::datatypes::{CommandId, CommandStatus, ToBytes};
use bytes::{Buf, BufMut, BytesMut};

#[derive(Clone, Debug, PartialEq)]
pub struct EnquireLink {
    // pub command_length: u32,
    // pub command_id: CommandId::EnquireLink,

    // EnquireLink always sets the command status to NULL
    // pub command_status: CommandStatus,
    pub sequence_number: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnquireLinkResponse {
    // pub command_length: u32,
    // pub command_id: CommandId::EnquireLinkResp,
    // EnquireLinkResponse instances always set the command status to ESME_ROK (CommandStatus::Ok)
    //pub command_status: CommandStatus,
    pub sequence_number: u32,
}

impl ToBytes for EnquireLink {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(12);

        // Write temporary data that we'll replace later with the actual length
        buffer.put_u32(0_u32);

        buffer.put_u32(CommandId::EnquireLink as u32);

        // EnquireLink always sets the command status to NULL
        buffer.put_u32(0u32);
        buffer.put_u32(self.sequence_number);

        // length should always be 12, but no harm in calculating it to avoid hard coding magic
        // values
        let length = buffer.len() as u32;

        let length_section = &mut buffer[0..][..4];
        length_section.copy_from_slice(&length.to_be_bytes());

        buffer.freeze().to_vec()
    }
}

impl ToBytes for EnquireLinkResponse {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(12);

        // Write temporary data that we'll replace later with the actual length
        buffer.put_u32(0_u32);

        buffer.put_u32(CommandId::EnquireLinkResp as u32);
        // EnquireLinkResponse instances always set the command status to ESME_ROK
        buffer.put_u32(CommandStatus::Ok as u32);
        buffer.put_u32(self.sequence_number);

        // length should always be 12, but no harm in calculating it to avoid hard coding magic
        // values
        let length = buffer.len() as u32;

        let length_section = &mut buffer[0..][..4];
        length_section.copy_from_slice(&length.to_be_bytes());

        buffer.freeze().to_vec()
    }
}
