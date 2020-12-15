mod bind_transmitter;
mod command_id;
mod command_status;
mod submit_sm;
mod unbind;

pub use bind_transmitter::{BindTransmitter, BindTransmitterResponse};
pub use submit_sm::{SubmitSm, SubmitSmResponse};
pub use unbind::{Unbind, UnbindResponse};

use bytes::{Bytes, Buf, BytesMut, BufMut};
pub use command_id::CommandId;
pub use command_status::CommandStatus;

#[derive(Clone, Debug, PartialEq)]
pub struct Tlv {
    pub tag: String,
    pub length: u32,
    pub value: Bytes,
}

pub trait ToBytes {
    /// Converts the provided data to bytes.
    fn to_bytes(&self) -> Vec<u8>;
}

impl ToBytes for Tlv {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(1024);

        buffer.put(self.tag.as_bytes());
        buffer.put_u32(self.length);
        buffer.extend_from_slice(self.value.bytes());

        let mut buf = vec![];
        buf.extend_from_slice(buffer.bytes());

        buf
    }
}