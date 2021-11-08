use crate::datatypes::numeric_plan_indicator::NumericPlanIndicator;
use crate::datatypes::priority_flag::PriorityFlag;
use crate::datatypes::tlv::Tlv;
use crate::datatypes::{CommandId, CommandStatus, ToBytes, TypeOfNumber};
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
    pub source_addr_ton: TypeOfNumber,
    pub source_addr_npi: NumericPlanIndicator,
    pub source_addr: String,
    pub dest_addr_ton: TypeOfNumber,
    pub dest_addr_npi: NumericPlanIndicator,
    pub destination_addr: String,
    pub esm_class: u8,
    pub protocol_id: u8,
    pub priority_flag: PriorityFlag,
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

impl ToBytes for SubmitSm {
    fn to_bytes(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(1024);

        // Write junk data that we'll replace later with the actual length
        buffer.put_u32(0_u32);

        buffer.put_u32(CommandId::SubmitSm as u32);
        buffer.put_u32(self.command_status as u32);
        buffer.put_u32(self.sequence_number);

        // Mandatory parameters
        buffer.put(self.service_type.as_bytes());
        buffer.put_u8(b'\0');

        buffer.put_u8(self.source_addr_ton as u8);
        buffer.put_u8(self.source_addr_npi as u8);

        buffer.put(self.source_addr.as_bytes());
        buffer.put_u8(b'\0');

        buffer.put_u8(self.dest_addr_ton as u8);
        buffer.put_u8(self.dest_addr_npi as u8);

        buffer.put(self.destination_addr.as_bytes());
        buffer.put_u8(b'\0');

        buffer.put_u8(self.esm_class);
        buffer.put_u8(self.protocol_id);
        buffer.put_u8(self.priority_flag as u8);

        buffer.put(self.schedule_delivery_time.as_bytes());
        buffer.put_u8(b'\0');

        buffer.put(self.validity_period.as_bytes());
        buffer.put_u8(b'\0');

        buffer.put_u8(self.registered_delivery);
        buffer.put_u8(self.replace_if_present_flag);
        buffer.put_u8(self.data_coding);
        buffer.put_u8(self.sm_default_msg_id);

        // If we are using the short message and short message length (sm_length) fields, then we
        // don't null terminate the string. the value of sm_length is used when reading.
        // todo: is the length of the short_message is greater than 254 octets, then message_payload
        //   should be used and sm_length set to 0.
        buffer.put_u8(self.sm_length);
        buffer.put(self.short_message.as_bytes());

        // Optional parameters

        if let Some(user_message_reference) = &self.user_message_reference {
            buffer.extend_from_slice(&user_message_reference.to_bytes());
        }

        if let Some(source_port) = &self.source_port {
            buffer.extend_from_slice(&source_port.to_bytes());
        }

        if let Some(source_addr_submit) = &self.source_addr_submit {
            buffer.extend_from_slice(&source_addr_submit.to_bytes());
        }

        if let Some(destination_port) = &self.destination_port {
            buffer.extend_from_slice(&destination_port.to_bytes());
        }

        if let Some(dest_addr_submit) = &self.dest_addr_submit {
            buffer.extend_from_slice(&dest_addr_submit.to_bytes());
        }

        if let Some(sar_msg_ref_num) = &self.sar_msg_ref_num {
            buffer.extend_from_slice(&sar_msg_ref_num.to_bytes());
        }

        if let Some(sar_total_segments) = &self.sar_total_segments {
            buffer.extend_from_slice(&sar_total_segments.to_bytes());
        }

        if let Some(sar_segment_seqnum) = &self.sar_segment_seqnum {
            buffer.extend_from_slice(&sar_segment_seqnum.to_bytes());
        }

        if let Some(more_messages_to_send) = &self.more_messages_to_send {
            buffer.extend_from_slice(&more_messages_to_send.to_bytes());
        }

        if let Some(payload_type) = &self.payload_type {
            buffer.extend_from_slice(&payload_type.to_bytes());
        }

        if let Some(message_payload) = &self.message_payload {
            buffer.extend_from_slice(&message_payload.to_bytes());
        }

        if let Some(privacy_indicator) = &self.privacy_indicator {
            buffer.extend_from_slice(&privacy_indicator.to_bytes());
        }

        if let Some(callback_num) = &self.callback_num {
            buffer.extend_from_slice(&callback_num.to_bytes());
        }

        if let Some(callback_num_pres_ind) = &self.callback_num_pres_ind {
            buffer.extend_from_slice(&callback_num_pres_ind.to_bytes());
        }

        if let Some(callback_num_atag) = &self.callback_num_atag {
            buffer.extend_from_slice(&callback_num_atag.to_bytes());
        }

        if let Some(source_subaddress) = &self.source_subaddress {
            buffer.extend_from_slice(&source_subaddress.to_bytes());
        }

        if let Some(source_subaddress) = &self.source_subaddress {
            buffer.extend_from_slice(&source_subaddress.to_bytes());
        }

        if let Some(dest_subaddress) = &self.dest_subaddress {
            buffer.extend_from_slice(&dest_subaddress.to_bytes());
        }

        if let Some(display_time) = &self.display_time {
            buffer.extend_from_slice(&display_time.to_bytes());
        }

        if let Some(sms_signal) = &self.sms_signal {
            buffer.extend_from_slice(&sms_signal.to_bytes());
        }

        if let Some(ms_validity) = &self.ms_validity {
            buffer.extend_from_slice(&ms_validity.to_bytes());
        }

        if let Some(ms_msg_wait_facilities) = &self.ms_msg_wait_facilities {
            buffer.extend_from_slice(&ms_msg_wait_facilities.to_bytes());
        }

        if let Some(number_of_messages) = &self.number_of_messages {
            buffer.extend_from_slice(&number_of_messages.to_bytes());
        }

        if let Some(alert_on_msg_delivery) = &self.alert_on_msg_delivery {
            buffer.extend_from_slice(&alert_on_msg_delivery.to_bytes());
        }

        if let Some(language_indicator) = &self.language_indicator {
            buffer.extend_from_slice(&language_indicator.to_bytes());
        }

        if let Some(its_reply_type) = &self.its_reply_type {
            buffer.extend_from_slice(&its_reply_type.to_bytes());
        }

        if let Some(its_session_info) = &self.its_session_info {
            buffer.extend_from_slice(&its_session_info.to_bytes());
        }

        if let Some(ussd_service_op) = &self.ussd_service_op {
            buffer.extend_from_slice(&ussd_service_op.to_bytes());
        }

        let length = buffer.len() as u32;

        let length_section = &mut buffer[0..][..4];
        length_section.copy_from_slice(&length.to_be_bytes());

        buffer.freeze()
    }
}

impl ToBytes for SubmitSmResponse {
    fn to_bytes(&self) -> Bytes {
        // The maximum size of the buffer needed is 77 octets for the command_id, command_status,
        // sequence_number, and message_id (65). The command length will be added on later.
        let mut buffer = BytesMut::with_capacity(77);

        // Write junk data that we'll replace later with the actual length
        buffer.put_u32(0_u32);

        buffer.put_u32(CommandId::SubmitSmResp as u32);
        buffer.put_u32(self.command_status as u32);
        buffer.put_u32(self.sequence_number);

        buffer.put(self.message_id.as_bytes());
        buffer.put_u8(b'\0');

        let length = buffer.len() as u32;

        let length_section = &mut buffer[0..][..4];
        length_section.copy_from_slice(&length.to_be_bytes());

        buffer.freeze()
    }
}
