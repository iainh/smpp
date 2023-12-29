use crate::datatypes::{CommandId, CommandStatus, ToBytes};
use bytes::{BufMut, Bytes, BytesMut};

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
    // EnquireLinkResponse instances always set the command status to ESME_ROK
    // (CommandStatus::Ok)
    //pub command_status: CommandStatus,
    pub sequence_number: u32,
}

impl ToBytes for EnquireLink {
    fn to_bytes(&self) -> Bytes {
        let length = 12;
        let mut buffer = BytesMut::with_capacity(length);

        buffer.put_u32(length as u32);
        buffer.put_u32(CommandId::EnquireLink as u32);
        // EnquireLink always sets the command status to NULL
        buffer.put_u32(0u32);
        buffer.put_u32(self.sequence_number);
        buffer.freeze()
    }
}

impl ToBytes for EnquireLinkResponse {
    fn to_bytes(&self) -> Bytes {
        let length = 12;
        let mut buffer = BytesMut::with_capacity(length);

        // Write temporary data that we'll replace later with the actual length
        buffer.put_u32(length as u32);

        buffer.put_u32(CommandId::EnquireLinkResp as u32);
        // EnquireLinkResponse instances always set the command status to
        // ESME_ROK
        buffer.put_u32(CommandStatus::Ok as u32);
        buffer.put_u32(self.sequence_number);

        buffer.freeze()
    }
}
