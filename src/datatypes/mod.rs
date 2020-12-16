mod bind_transmitter;
mod command_id;
mod command_status;
mod submit_sm;
mod tlv;
mod unbind;

pub use bind_transmitter::{BindTransmitter, BindTransmitterResponse};
pub(crate) use command_id::CommandId;
pub use command_status::CommandStatus;
pub use submit_sm::{SubmitSm, SubmitSmResponse};
pub use tlv::Tlv;
pub use unbind::{Unbind, UnbindResponse};

use bytes::{Buf, BufMut, Bytes, BytesMut};

pub trait ToBytes {
    /// Converts the provided data to bytes.
    fn to_bytes(&self) -> Vec<u8>;
}
