use crate::{CommandId, CommandStatus};

/// The purpose of the SMPP unbind operation is to deregister an instance of an ESME from the SMSC
/// and inform the SMSC that the ESME no longer wishes to use this network connection for the
/// submission or delivery of messages.
///
/// Thus, the unbind operation may be viewed as a form of SMSC logoff request to close the current
/// SMPP session.
#[derive(Clone, Debug, PartialEq)]
pub struct Unbind {
    // pub command_length: u32,
    // pub command_id: CommandId::Unbind,
    pub command_status: CommandStatus,
    pub sequence_number: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UnbindResponse {
    // pub command_length: u32,
    // pub command_id: CommandId::UnbindResponse,
    pub command_status: CommandStatus,
    pub sequence_number: u32,
}
