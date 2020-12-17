mod bind_transmitter;
mod command_id;
mod command_status;
mod numeric_plan_indicator;
mod submit_sm;
mod tlv;
mod type_of_number;
mod unbind;

pub use bind_transmitter::{BindTransmitter, BindTransmitterResponse};
pub(crate) use command_id::CommandId;
pub use command_status::CommandStatus;
pub use numeric_plan_indicator::NumericPlanIndicator;
pub use submit_sm::{SubmitSm, SubmitSmResponse};
pub use tlv::Tlv;
pub use type_of_number::TypeOfNumber;
pub use unbind::{Unbind, UnbindResponse};

pub trait ToBytes {
    /// Converts the provided data to bytes.
    fn to_bytes(&self) -> Vec<u8>;
}
