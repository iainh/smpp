use crate::datatypes::Tlv;
use crate::{CommandId, CommandStatus};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// This operation is used by an ESME to submit a short message to the SMSC for onward transmission
/// to a specified short message entity (SME). The submit_sm PDU does not support the transaction
/// message mode.
#[derive(Clone, Debug, PartialEq)]
pub struct SubmitSm {
    // pub command_length: u32,
    // pub command_id: CommandId::SubmitSm,
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Mandatory parameters
    pub service_type: String,
    pub source_addr_ton: u8,
    pub source_addr_npi: u8,
    pub source_addr: String,
    pub dest_addr_ton: u8,
    pub dest_addr_npi: u8,
    pub esm_class: u8,
    pub protocol_id: u8,
    pub priority_flag: u8,
    pub schedule_delivery_time: String,
    pub validity_period: String,
    pub registered_delivery: u8,
    pub replace_if_present_flag: u8,
    pub data_coding: u8,
    pub sm_default_msg_id: u8,
    pub sm_length: u8,
    pub short_message: String,

    // Optional parameters
    pub user_message_reference: Option<Tlv>,
    pub source_port: Option<Tlv>,
    pub source_addr_submit: Option<Tlv>,
    pub destination_port: Option<Tlv>,
    pub dest_addr_submit: Option<Tlv>,
    pub sar_msg_ref_num: Option<Tlv>,
    pub sar_total_segments: Option<Tlv>,
    pub sar_segment_seqnum: Option<Tlv>,
    pub more_messages_to_send: Option<Tlv>,
    pub payload_type: Option<Tlv>,
    pub message_payload: Option<Tlv>,
    pub privacy_indicator: Option<Tlv>,
    pub callback_num: Option<Tlv>,
    pub callback_num_pres_ind: Option<Tlv>,
    pub callback_num_atag: Option<Tlv>,
    pub source_subaddress: Option<Tlv>,
    pub dest_subaddress: Option<Tlv>,
    pub display_time: Option<Tlv>,
    pub sms_signal: Option<Tlv>,
    pub ms_validity: Option<Tlv>,
    pub ms_msg_wait_facilities: Option<Tlv>,
    pub number_of_messages: Option<Tlv>,
    pub alert_on_msg_delivery: Option<Tlv>,
    pub language_indicator: Option<Tlv>,
    pub its_reply_type: Option<Tlv>,
    pub its_session_info: Option<Tlv>,
    pub ussd_service_op: Option<Tlv>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SubmitSmResponse {
    // pub command_length: u32,
    // pub command_id: CommandId::SubmitSmResp,
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Body
    pub message_id: String,
}
