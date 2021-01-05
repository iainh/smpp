mod bind_transmitter;
mod command_id;
mod command_status;
mod enquire_link;
mod interface_version;
mod numeric_plan_indicator;
mod priority_flag;
mod submit_sm;
mod tlv;
mod type_of_number;
mod unbind;

pub(crate) use command_id::CommandId;
pub use command_status::CommandStatus;
pub use interface_version::InterfaceVersion;
pub use numeric_plan_indicator::NumericPlanIndicator;
pub use priority_flag::PriorityFlag;
pub use tlv::Tlv;
pub use type_of_number::TypeOfNumber;

pub use bind_transmitter::{BindTransmitter, BindTransmitterResponse};
pub use enquire_link::{EnquireLink, EnquireLinkResponse};
pub use submit_sm::{SubmitSm, SubmitSmResponse};
pub use unbind::{Unbind, UnbindResponse};

pub trait ToBytes {
    /// Converts the provided data to bytes.
    fn to_bytes(&self) -> Vec<u8>;
}
