use crate::datatypes::Tlv;
use crate::{CommandId, CommandStatus};
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Clone, Debug, PartialEq)]
pub struct BindTransmitter {
    // pub command_length: u32,
    // pub command_id: CommandId::BindTransmitter,
    pub command_status: CommandStatus,
    pub sequence_number: u32,
    // body
    pub system_id: String,
    pub password: String,
    pub system_type: String,
    pub interface_version: u8,
    pub addr_ton: u8,
    pub addr_npi: u8,
    pub address_range: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BindTransmitterResponse {
    // pub command_length: u32,
    // pub command_id: CommandId,
    pub command_status: CommandStatus,
    pub sequence_number: u32,
    // body
    pub system_id: String,
    pub sc_interface_version: Option<Tlv>,
}
