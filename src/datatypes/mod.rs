mod address;
mod bind_receiver;
mod bind_transceiver;
mod bind_transmitter;
mod cancel_sm;
mod command_id;
mod command_status;
mod data_coding;
mod data_sm;
mod datetime;
mod deliver_sm;
mod enquire_link;
mod esm_class;
mod fixed_string;
mod generic_nack;
mod interface_version;
mod numeric_plan_indicator;
mod outbind;
mod priority_flag;
mod query_sm;
mod replace_sm;
mod service_type;
mod submit_sm;
mod tlv;
mod type_of_number;
mod unbind;

pub use address::{AddressError, AlphanumericAddress, DestinationAddr, PhoneNumber, SourceAddr};
pub(crate) use command_id::CommandId;
pub use command_status::CommandStatus;
pub use data_coding::{DataCoding, DataCodingError, MessageClass};
pub use datetime::{DateTimeError, ScheduleDeliveryTime, SmppDateTime, ValidityPeriod};
pub use esm_class::{
    EsmClass, EsmClassError, EsmFeatures, MessageMode, MessageType, StoreAndForwardType,
};
pub use fixed_string::{
    AddressRange, FixedString, FixedStringError, MessageId, Password, ShortMessage, SystemId,
    SystemType,
};
pub use interface_version::InterfaceVersion;
pub use numeric_plan_indicator::NumericPlanIndicator;
pub use priority_flag::PriorityFlag;
pub use service_type::{ServiceType, ServiceTypeError};
pub use tlv::{Tlv, tags};
pub use type_of_number::TypeOfNumber;

pub use bind_receiver::{BindReceiver, BindReceiverResponse, BindReceiverValidationError};
pub use bind_transceiver::{
    BindTransceiver, BindTransceiverResponse, BindTransceiverValidationError,
};
pub use bind_transmitter::{
    BindTransmitter, BindTransmitterResponse, BindTransmitterValidationError,
};
pub use cancel_sm::{
    CancelSm, CancelSmResponse, CancelSmResponseValidationError, CancelSmValidationError,
};
pub use data_sm::{
    DataSm, DataSmResponse, DataSmResponseValidationError, DataSmValidationError,
};
pub use deliver_sm::{DeliverSm, DeliverSmResponse, DeliverSmValidationError};
pub use enquire_link::{EnquireLink, EnquireLinkResponse};
pub use generic_nack::GenericNack;
pub use outbind::{Outbind, OutbindValidationError};
pub use query_sm::{
    MessageState, QuerySm, QuerySmResponse, QuerySmResponseValidationError, QuerySmValidationError,
};
pub use replace_sm::{
    ReplaceSm, ReplaceSmResponse, ReplaceSmResponseValidationError, ReplaceSmValidationError,
};
pub use submit_sm::{SubmitSm, SubmitSmResponse, SubmitSmValidationError};
pub use unbind::{Unbind, UnbindResponse};

// SMPP v3.4 specification field length limits (excluding null terminator)
// These constants are shared across multiple PDU types
pub const MAX_SYSTEM_ID_LENGTH: usize = 15;
pub const MAX_PASSWORD_LENGTH: usize = 8;
