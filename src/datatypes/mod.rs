mod bind_transmitter;
mod command_id;
mod command_status;

pub use bind_transmitter::{BindTransmitter, BindTransmitterResponse};
use bytes::Bytes;
pub use command_id::CommandId;
pub use command_status::CommandStatus;

#[derive(Clone, Debug, PartialEq)]
pub struct Tlv {
    pub tag: String,
    pub length: u32,
    pub value: Bytes,
}
