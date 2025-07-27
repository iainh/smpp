use crate::datatypes::{CommandId, CommandStatus};
use crate::macros::impl_complete_header_only_pdu;

#[derive(Clone, Debug, PartialEq)]
pub struct EnquireLink {
    // pub command_length: u32,
    // pub command_id: CommandId::EnquireLink,

    // EnquireLink always sets the command status to NULL
    pub command_status: CommandStatus,
    pub sequence_number: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnquireLinkResponse {
    // pub command_length: u32,
    // pub command_id: CommandId::EnquireLinkResp,
    // EnquireLinkResponse instances always set the command status to ESME_ROK
    // (CommandStatus::Ok)
    pub command_status: CommandStatus,
    pub sequence_number: u32,
}

// Use macros to generate all boilerplate code
impl_complete_header_only_pdu!(EnquireLink, CommandId::EnquireLink);
impl_complete_header_only_pdu!(EnquireLinkResponse, CommandId::EnquireLinkResp);
