use crate::datatypes::numeric_plan_indicator::NumericPlanIndicator;
use crate::datatypes::priority_flag::PriorityFlag;
use crate::datatypes::tlv::Tlv;
use crate::datatypes::{CommandId, CommandStatus, ToBytes, TypeOfNumber};
use bytes::{BufMut, Bytes, BytesMut};

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

#[derive(Debug, thiserror::Error)]
pub enum SubmitSmValidationError {
    #[error(
        "service_type exceeds maximum length of 5 characters (6 with null terminator): {actual}"
    )]
    ServiceTypeTooLong { actual: usize },

    #[error(
        "source_addr exceeds maximum length of 20 characters (21 with null terminator): {actual}"
    )]
    SourceAddrTooLong { actual: usize },

    #[error("destination_addr exceeds maximum length of 20 characters (21 with null terminator): {actual}")]
    DestinationAddrTooLong { actual: usize },

    #[error("schedule_delivery_time exceeds maximum length of 16 characters (17 with null terminator): {actual}")]
    ScheduleDeliveryTimeTooLong { actual: usize },

    #[error("validity_period exceeds maximum length of 16 characters (17 with null terminator): {actual}")]
    ValidityPeriodTooLong { actual: usize },

    #[error("sm_length ({sm_length}) does not match short_message length ({message_length})")]
    SmLengthMismatch {
        sm_length: u8,
        message_length: usize,
    },

    #[error("short_message exceeds maximum length of 254 bytes (use message_payload TLV for longer messages): {actual}")]
    ShortMessageTooLong { actual: usize },

    #[error("Cannot use both short_message and message_payload - they are mutually exclusive")]
    MutualExclusivityViolation,
}

impl SubmitSm {
    /// Validates the SubmitSm PDU according to SMPP v3.4 specification
    pub fn validate(&self) -> Result<(), SubmitSmValidationError> {
        // Validate field length constraints
        if self.service_type.len() > 5 {
            return Err(SubmitSmValidationError::ServiceTypeTooLong {
                actual: self.service_type.len(),
            });
        }

        if self.source_addr.len() > 20 {
            return Err(SubmitSmValidationError::SourceAddrTooLong {
                actual: self.source_addr.len(),
            });
        }

        if self.destination_addr.len() > 20 {
            return Err(SubmitSmValidationError::DestinationAddrTooLong {
                actual: self.destination_addr.len(),
            });
        }

        if self.schedule_delivery_time.len() > 16 {
            return Err(SubmitSmValidationError::ScheduleDeliveryTimeTooLong {
                actual: self.schedule_delivery_time.len(),
            });
        }

        if self.validity_period.len() > 16 {
            return Err(SubmitSmValidationError::ValidityPeriodTooLong {
                actual: self.validity_period.len(),
            });
        }

        // Validate sm_length matches actual short_message length
        if self.sm_length as usize != self.short_message.len() {
            return Err(SubmitSmValidationError::SmLengthMismatch {
                sm_length: self.sm_length,
                message_length: self.short_message.len(),
            });
        }

        // Validate short message length constraints
        if self.short_message.len() > 254 {
            return Err(SubmitSmValidationError::ShortMessageTooLong {
                actual: self.short_message.len(),
            });
        }

        // Validate mutual exclusivity
        if !self.short_message.is_empty() && self.message_payload.is_some() {
            return Err(SubmitSmValidationError::MutualExclusivityViolation);
        }

        Ok(())
    }

    /// Creates a builder for constructing SubmitSm PDUs with validation
    pub fn builder() -> SubmitSmBuilder {
        SubmitSmBuilder::new()
    }
}

/// Builder for creating SubmitSm PDUs with validation and sensible defaults
pub struct SubmitSmBuilder {
    command_status: CommandStatus,
    sequence_number: u32,
    service_type: String,
    source_addr_ton: TypeOfNumber,
    source_addr_npi: NumericPlanIndicator,
    source_addr: String,
    dest_addr_ton: TypeOfNumber,
    dest_addr_npi: NumericPlanIndicator,
    destination_addr: String,
    esm_class: u8,
    protocol_id: u8,
    priority_flag: PriorityFlag,
    schedule_delivery_time: String,
    validity_period: String,
    registered_delivery: u8,
    replace_if_present_flag: u8,
    data_coding: u8,
    sm_default_msg_id: u8,
    short_message: String,
    // Optional TLVs
    user_message_reference: Option<Tlv>,
    source_port: Option<Tlv>,
    source_addr_submit: Option<Tlv>,
    destination_port: Option<Tlv>,
    dest_addr_submit: Option<Tlv>,
    sar_msg_ref_num: Option<Tlv>,
    sar_total_segments: Option<Tlv>,
    sar_segment_seqnum: Option<Tlv>,
    more_messages_to_send: Option<Tlv>,
    payload_type: Option<Tlv>,
    message_payload: Option<Tlv>,
    privacy_indicator: Option<Tlv>,
    callback_num: Option<Tlv>,
    callback_num_pres_ind: Option<Tlv>,
    callback_num_atag: Option<Tlv>,
    source_subaddress: Option<Tlv>,
    dest_subaddress: Option<Tlv>,
    display_time: Option<Tlv>,
    sms_signal: Option<Tlv>,
    ms_validity: Option<Tlv>,
    ms_msg_wait_facilities: Option<Tlv>,
    number_of_messages: Option<Tlv>,
    alert_on_msg_delivery: Option<Tlv>,
    language_indicator: Option<Tlv>,
    its_reply_type: Option<Tlv>,
    its_session_info: Option<Tlv>,
    ussd_service_op: Option<Tlv>,
    sm_length: u8,
}

impl Default for SubmitSmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SubmitSmBuilder {
    pub fn new() -> Self {
        Self {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: String::new(),
            source_addr_ton: TypeOfNumber::Unknown,
            source_addr_npi: NumericPlanIndicator::Unknown,
            source_addr: String::new(),
            dest_addr_ton: TypeOfNumber::Unknown,
            dest_addr_npi: NumericPlanIndicator::Unknown,
            destination_addr: String::new(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: String::new(),
            validity_period: String::new(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            short_message: String::new(),
            sm_length: 0,
            user_message_reference: None,
            source_port: None,
            source_addr_submit: None,
            destination_port: None,
            dest_addr_submit: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            more_messages_to_send: None,
            payload_type: None,
            message_payload: None,
            privacy_indicator: None,
            callback_num: None,
            callback_num_pres_ind: None,
            callback_num_atag: None,
            source_subaddress: None,
            dest_subaddress: None,
            display_time: None,
            sms_signal: None,
            ms_validity: None,
            ms_msg_wait_facilities: None,
            number_of_messages: None,
            alert_on_msg_delivery: None,
            language_indicator: None,
            its_reply_type: None,
            its_session_info: None,
            ussd_service_op: None,
        }
    }

    pub fn sequence_number(mut self, seq: u32) -> Self {
        self.sequence_number = seq;
        self
    }

    pub fn service_type(mut self, service_type: impl Into<String>) -> Self {
        self.service_type = service_type.into();
        self
    }

    pub fn source_addr(mut self, addr: impl Into<String>) -> Self {
        self.source_addr = addr.into();
        self
    }

    pub fn destination_addr(mut self, addr: impl Into<String>) -> Self {
        self.destination_addr = addr.into();
        self
    }

    pub fn source_addr_ton(mut self, ton: TypeOfNumber) -> Self {
        self.source_addr_ton = ton;
        self
    }

    pub fn source_addr_npi(mut self, npi: NumericPlanIndicator) -> Self {
        self.source_addr_npi = npi;
        self
    }

    pub fn dest_addr_ton(mut self, ton: TypeOfNumber) -> Self {
        self.dest_addr_ton = ton;
        self
    }

    pub fn dest_addr_npi(mut self, npi: NumericPlanIndicator) -> Self {
        self.dest_addr_npi = npi;
        self
    }

    pub fn short_message(mut self, message: impl Into<String>) -> Self {
        self.short_message = message.into();
        self
    }

    pub fn priority_flag(mut self, priority: PriorityFlag) -> Self {
        self.priority_flag = priority;
        self
    }

    pub fn registered_delivery(mut self, delivery: u8) -> Self {
        self.registered_delivery = delivery;
        self
    }

    pub fn user_message_reference(mut self, tlv: Tlv) -> Self {
        self.user_message_reference = Some(tlv);
        self
    }

    pub fn source_port(mut self, tlv: Tlv) -> Self {
        self.source_port = Some(tlv);
        self
    }

    pub fn message_payload(mut self, tlv: Tlv) -> Self {
        self.message_payload = Some(tlv);
        self
    }

    /// Build the SubmitSm, performing validation and calculating sm_length automatically
    pub fn build(mut self) -> Result<SubmitSm, SubmitSmValidationError> {
        // Auto-calculate sm_length from short_message
        self.sm_length = self.short_message.len() as u8;

        let submit_sm = SubmitSm {
            command_status: self.command_status,
            sequence_number: self.sequence_number,
            service_type: self.service_type,
            source_addr_ton: self.source_addr_ton,
            source_addr_npi: self.source_addr_npi,
            source_addr: self.source_addr,
            dest_addr_ton: self.dest_addr_ton,
            dest_addr_npi: self.dest_addr_npi,
            destination_addr: self.destination_addr,
            esm_class: self.esm_class,
            protocol_id: self.protocol_id,
            priority_flag: self.priority_flag,
            schedule_delivery_time: self.schedule_delivery_time,
            validity_period: self.validity_period,
            registered_delivery: self.registered_delivery,
            replace_if_present_flag: self.replace_if_present_flag,
            data_coding: self.data_coding,
            sm_default_msg_id: self.sm_default_msg_id,
            sm_length: self.sm_length,
            short_message: self.short_message,
            user_message_reference: self.user_message_reference,
            source_port: self.source_port,
            source_addr_submit: self.source_addr_submit,
            destination_port: self.destination_port,
            dest_addr_submit: self.dest_addr_submit,
            sar_msg_ref_num: self.sar_msg_ref_num,
            sar_total_segments: self.sar_total_segments,
            sar_segment_seqnum: self.sar_segment_seqnum,
            more_messages_to_send: self.more_messages_to_send,
            payload_type: self.payload_type,
            message_payload: self.message_payload,
            privacy_indicator: self.privacy_indicator,
            callback_num: self.callback_num,
            callback_num_pres_ind: self.callback_num_pres_ind,
            callback_num_atag: self.callback_num_atag,
            source_subaddress: self.source_subaddress,
            dest_subaddress: self.dest_subaddress,
            display_time: self.display_time,
            sms_signal: self.sms_signal,
            ms_validity: self.ms_validity,
            ms_msg_wait_facilities: self.ms_msg_wait_facilities,
            number_of_messages: self.number_of_messages,
            alert_on_msg_delivery: self.alert_on_msg_delivery,
            language_indicator: self.language_indicator,
            its_reply_type: self.its_reply_type,
            its_session_info: self.its_session_info,
            ussd_service_op: self.ussd_service_op,
        };

        // Validate before returning
        submit_sm.validate()?;
        Ok(submit_sm)
    }
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
        // Validate field constraints per SMPP v3.4 specification
        self.validate().expect("SubmitSm validation failed");

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

        // If we are using the short message and short message length
        // (sm_length) fields, then we
        // don't null terminate the string. the value of sm_length is used when
        // reading.
        // TODO: is the length of the short_message is greater than 254 octets,
        //       then message_payload should be used and sm_length set to 0.
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
        let length = 17 + self.message_id.len();

        let mut buffer = BytesMut::with_capacity(length);

        // Write junk data that we'll replace later with the actual length
        buffer.put_u32(length as u32);

        buffer.put_u32(CommandId::SubmitSmResp as u32);
        buffer.put_u32(self.command_status as u32);
        buffer.put_u32(self.sequence_number);

        buffer.put(self.message_id.as_bytes());
        buffer.put_u8(b'\0');

        buffer.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn submit_sm_to_bytes_basic() {
        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: "".to_string(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: "1234567890".to_string(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: "0987654321".to_string(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 11,
            short_message: "Hello World".to_string(),
            // All optional parameters set to None
            user_message_reference: None,
            source_port: None,
            source_addr_submit: None,
            destination_port: None,
            dest_addr_submit: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            more_messages_to_send: None,
            payload_type: None,
            message_payload: None,
            privacy_indicator: None,
            callback_num: None,
            callback_num_pres_ind: None,
            callback_num_atag: None,
            source_subaddress: None,
            dest_subaddress: None,
            display_time: None,
            sms_signal: None,
            ms_validity: None,
            ms_msg_wait_facilities: None,
            number_of_messages: None,
            alert_on_msg_delivery: None,
            language_indicator: None,
            its_reply_type: None,
            its_session_info: None,
            ussd_service_op: None,
        };

        let bytes = submit_sm.to_bytes();

        // Verify header
        assert_eq!(&bytes[0..4], &(bytes.len() as u32).to_be_bytes()); // command_length
        assert_eq!(&bytes[4..8], &(CommandId::SubmitSm as u32).to_be_bytes()); // command_id
        assert_eq!(&bytes[8..12], &(CommandStatus::Ok as u32).to_be_bytes()); // command_status
        assert_eq!(&bytes[12..16], &1u32.to_be_bytes()); // sequence_number

        // Verify some key fields
        let body_start = 16;
        assert_eq!(bytes[body_start], 0); // service_type null terminator
        assert_eq!(bytes[body_start + 1], TypeOfNumber::International as u8);
        assert_eq!(bytes[body_start + 2], NumericPlanIndicator::Isdn as u8);

        // Check that short message is included
        let message_bytes = "Hello World".as_bytes();
        assert!(bytes
            .windows(message_bytes.len())
            .any(|window| window == message_bytes));
    }

    #[test]
    fn submit_sm_to_bytes_with_optional_parameters() {
        let user_msg_ref_tlv = Tlv {
            tag: 0x0204,
            length: 2,
            value: Bytes::from_static(&[0x00, 0x01]),
        };

        let source_port_tlv = Tlv {
            tag: 0x020A,
            length: 2,
            value: Bytes::from_static(&[0x1F, 0x90]),
        };

        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: "".to_string(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: "1234567890".to_string(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: "0987654321".to_string(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 11,
            short_message: "Hello World".to_string(),
            user_message_reference: Some(user_msg_ref_tlv),
            source_port: Some(source_port_tlv),
            source_addr_submit: None,
            destination_port: None,
            dest_addr_submit: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            more_messages_to_send: None,
            payload_type: None,
            message_payload: None,
            privacy_indicator: None,
            callback_num: None,
            callback_num_pres_ind: None,
            callback_num_atag: None,
            source_subaddress: None,
            dest_subaddress: None,
            display_time: None,
            sms_signal: None,
            ms_validity: None,
            ms_msg_wait_facilities: None,
            number_of_messages: None,
            alert_on_msg_delivery: None,
            language_indicator: None,
            its_reply_type: None,
            its_session_info: None,
            ussd_service_op: None,
        };

        let bytes = submit_sm.to_bytes();

        // Should include TLV data at the end
        let tlv1_bytes = [0x02, 0x04, 0x00, 0x02, 0x00, 0x01]; // user_message_reference TLV
        let tlv2_bytes = [0x02, 0x0A, 0x00, 0x02, 0x1F, 0x90]; // source_port TLV

        assert!(bytes
            .windows(tlv1_bytes.len())
            .any(|window| window == tlv1_bytes));
        assert!(bytes
            .windows(tlv2_bytes.len())
            .any(|window| window == tlv2_bytes));
    }

    #[test]
    fn submit_sm_response_to_bytes() {
        let submit_sm_response = SubmitSmResponse {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            message_id: "msg123456789".to_string(),
        };

        let bytes = submit_sm_response.to_bytes();

        // Verify header
        assert_eq!(&bytes[0..4], &(bytes.len() as u32).to_be_bytes()); // command_length
        assert_eq!(
            &bytes[4..8],
            &(CommandId::SubmitSmResp as u32).to_be_bytes()
        ); // command_id
        assert_eq!(&bytes[8..12], &(CommandStatus::Ok as u32).to_be_bytes()); // command_status
        assert_eq!(&bytes[12..16], &1u32.to_be_bytes()); // sequence_number

        // Check message_id is included with null terminator
        let expected_msg_id = "msg123456789\0".as_bytes();
        assert_eq!(&bytes[16..16 + expected_msg_id.len()], expected_msg_id);
    }

    #[test]
    fn submit_sm_response_to_bytes_empty_message_id() {
        let submit_sm_response = SubmitSmResponse {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            message_id: "".to_string(),
        };

        let bytes = submit_sm_response.to_bytes();

        // Should be minimum size: 16 bytes header + 1 byte null terminator
        assert_eq!(bytes.len(), 17);
        assert_eq!(bytes[16], 0); // null terminator
    }

    #[test]
    fn submit_sm_response_with_error_status() {
        let submit_sm_response = SubmitSmResponse {
            command_status: CommandStatus::InvalidSourceAddress,
            sequence_number: 1,
            message_id: "".to_string(),
        };

        let bytes = submit_sm_response.to_bytes();

        // Verify error status is encoded correctly
        assert_eq!(
            &bytes[8..12],
            &(CommandStatus::InvalidSourceAddress as u32).to_be_bytes()
        );
    }

    #[test]
    #[should_panic(expected = "SmLengthMismatch")]
    fn submit_sm_validation_sm_length_mismatch() {
        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: "".to_string(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: "1234567890".to_string(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: "0987654321".to_string(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 5, // Wrong length - should be 11
            short_message: "Hello World".to_string(),
            user_message_reference: None,
            source_port: None,
            source_addr_submit: None,
            destination_port: None,
            dest_addr_submit: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            more_messages_to_send: None,
            payload_type: None,
            message_payload: None,
            privacy_indicator: None,
            callback_num: None,
            callback_num_pres_ind: None,
            callback_num_atag: None,
            source_subaddress: None,
            dest_subaddress: None,
            display_time: None,
            sms_signal: None,
            ms_validity: None,
            ms_msg_wait_facilities: None,
            number_of_messages: None,
            alert_on_msg_delivery: None,
            language_indicator: None,
            its_reply_type: None,
            its_session_info: None,
            ussd_service_op: None,
        };

        let _ = submit_sm.to_bytes(); // Should panic
    }

    #[test]
    #[should_panic(expected = "ServiceTypeTooLong")]
    fn submit_sm_validation_service_type_too_long() {
        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: "TOOLONG".to_string(), // 7 chars, max is 5
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: "1234567890".to_string(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: "0987654321".to_string(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 0,
            short_message: "".to_string(),
            user_message_reference: None,
            source_port: None,
            source_addr_submit: None,
            destination_port: None,
            dest_addr_submit: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            more_messages_to_send: None,
            payload_type: None,
            message_payload: None,
            privacy_indicator: None,
            callback_num: None,
            callback_num_pres_ind: None,
            callback_num_atag: None,
            source_subaddress: None,
            dest_subaddress: None,
            display_time: None,
            sms_signal: None,
            ms_validity: None,
            ms_msg_wait_facilities: None,
            number_of_messages: None,
            alert_on_msg_delivery: None,
            language_indicator: None,
            its_reply_type: None,
            its_session_info: None,
            ussd_service_op: None,
        };

        let _ = submit_sm.to_bytes(); // Should panic
    }

    #[test]
    #[should_panic(expected = "SourceAddrTooLong")]
    fn submit_sm_validation_source_addr_too_long() {
        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: "".to_string(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: "A".repeat(21), // 21 chars, max is 20
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: "0987654321".to_string(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 0,
            short_message: "".to_string(),
            user_message_reference: None,
            source_port: None,
            source_addr_submit: None,
            destination_port: None,
            dest_addr_submit: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            more_messages_to_send: None,
            payload_type: None,
            message_payload: None,
            privacy_indicator: None,
            callback_num: None,
            callback_num_pres_ind: None,
            callback_num_atag: None,
            source_subaddress: None,
            dest_subaddress: None,
            display_time: None,
            sms_signal: None,
            ms_validity: None,
            ms_msg_wait_facilities: None,
            number_of_messages: None,
            alert_on_msg_delivery: None,
            language_indicator: None,
            its_reply_type: None,
            its_session_info: None,
            ussd_service_op: None,
        };

        let _ = submit_sm.to_bytes(); // Should panic
    }

    #[test]
    #[should_panic(expected = "ShortMessageTooLong")]
    fn submit_sm_validation_short_message_too_long() {
        let long_message = "A".repeat(255); // 255 chars, max is 254
        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: "".to_string(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: "1234567890".to_string(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: "0987654321".to_string(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 255,
            short_message: long_message,
            user_message_reference: None,
            source_port: None,
            source_addr_submit: None,
            destination_port: None,
            dest_addr_submit: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            more_messages_to_send: None,
            payload_type: None,
            message_payload: None,
            privacy_indicator: None,
            callback_num: None,
            callback_num_pres_ind: None,
            callback_num_atag: None,
            source_subaddress: None,
            dest_subaddress: None,
            display_time: None,
            sms_signal: None,
            ms_validity: None,
            ms_msg_wait_facilities: None,
            number_of_messages: None,
            alert_on_msg_delivery: None,
            language_indicator: None,
            its_reply_type: None,
            its_session_info: None,
            ussd_service_op: None,
        };

        let _ = submit_sm.to_bytes(); // Should panic
    }

    #[test]
    #[should_panic(expected = "MutualExclusivityViolation")]
    fn submit_sm_validation_mutual_exclusivity() {
        use bytes::Bytes;

        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: "".to_string(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: "1234567890".to_string(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: "0987654321".to_string(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 5,
            short_message: "Hello".to_string(), // Has short message
            user_message_reference: None,
            source_port: None,
            source_addr_submit: None,
            destination_port: None,
            dest_addr_submit: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            more_messages_to_send: None,
            payload_type: None,
            message_payload: Some(Tlv {
                // Also has message payload - should fail
                tag: 0x0424,
                length: 10,
                value: Bytes::from_static(b"Some data!"),
            }),
            privacy_indicator: None,
            callback_num: None,
            callback_num_pres_ind: None,
            callback_num_atag: None,
            source_subaddress: None,
            dest_subaddress: None,
            display_time: None,
            sms_signal: None,
            ms_validity: None,
            ms_msg_wait_facilities: None,
            number_of_messages: None,
            alert_on_msg_delivery: None,
            language_indicator: None,
            its_reply_type: None,
            its_session_info: None,
            ussd_service_op: None,
        };

        let _ = submit_sm.to_bytes(); // Should panic
    }
}
