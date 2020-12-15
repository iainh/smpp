use crate::datatypes::{Tlv, ToBytes};
use crate::{CommandId, CommandStatus};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::ptr::null;

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

impl ToBytes for BindTransmitter {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(1024);

        buffer.put_u32(CommandId::BindTransmitter as u32);
        buffer.put_u32(self.command_status as u32);
        buffer.put_u32(self.sequence_number);
        buffer.put(self.system_id.as_bytes());
        buffer.put(self.password.as_bytes());
        buffer.put(self.system_type.as_bytes());
        buffer.put_u8(self.interface_version);
        buffer.put_u8(self.addr_ton);
        buffer.put_u8(self.addr_npi);
        buffer.put(self.address_range.as_bytes());

        let length = (buffer.len() + 4) as u32;

        let mut buf = vec![];
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(buffer.bytes());

        buf
    }
}

impl ToBytes for BindTransmitterResponse {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(1024);

        buffer.put_u32(CommandId::BindTransmitter as u32);
        buffer.put_u32(self.command_status as u32);
        buffer.put_u32(self.sequence_number);

        if let Some(sc_interface_version) = &self.sc_interface_version {
            buffer.extend_from_slice(&sc_interface_version.to_bytes());
        } else {
            // todo: is this right?
            buffer.put_u8(b'\0');
        }

        let length = (buffer.len() + 4) as u32;

        let mut buf = vec![];
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(buffer.bytes());

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};
    use std::convert::TryInto;
    use std::io::{Cursor, Write};

    # [test]
    fn bind_transmitter_to_bytes() {
        let bind_transmitter = BindTransmitter {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            system_id: "system_id".to_string(),
            password: "password".to_string(),
            system_type: "system_type".to_string(),
            interface_version: 12,
            addr_ton: 87,
            addr_npi: 89,
            address_range: "???".to_string()
        };

        let bt_bytes = bind_transmitter.to_bytes();

        assert_eq!(50, bt_bytes.len());

        println!("{:x?}", bt_bytes);

    }
}