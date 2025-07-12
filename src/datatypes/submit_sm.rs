use crate::datatypes::numeric_plan_indicator::NumericPlanIndicator;
use crate::datatypes::priority_flag::PriorityFlag;
use crate::datatypes::tlv::Tlv;
use crate::datatypes::{
    CommandId, CommandStatus, ToBytes, TypeOfNumber, ServiceType, SourceAddr, DestinationAddr,
    ScheduleDeliveryTime, ValidityPeriod, MessageId, ShortMessage,
};
use bytes::{BufMut, Bytes, BytesMut};

// SMPP v3.4 specification field length limits (excluding null terminator)
// MAX_SHORT_MESSAGE_LENGTH is now enforced by the ShortMessage type

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
    /// 4.1.1 service_type: The service_type parameter can be used to indicate the SMS
    ///       Application service associated with the message. Specifying the service_type
    ///       allows the ESME to avail of enhanced messaging services such as "replace by
    ///       service_type" or to control the teleservice used on the air interface. Set to
    ///       NULL if not applicable. Max length: 5 octets (6 with null terminator).
    pub service_type: ServiceType,

    /// 4.1.2 source_addr_ton: Type of Number for source address. If not known, set to NULL.
    pub source_addr_ton: TypeOfNumber,

    /// 4.1.3 source_addr_npi: Numbering Plan Indicator for source address. If not known, set to NULL.
    pub source_addr_npi: NumericPlanIndicator,

    /// 4.1.4 source_addr: Address of SME which originated this message. If not known, set to NULL.
    ///       Max length: 20 octets (21 with null terminator).
    pub source_addr: SourceAddr,

    /// 4.1.5 dest_addr_ton: Type of Number for destination address.
    pub dest_addr_ton: TypeOfNumber,

    /// 4.1.6 dest_addr_npi: Numbering Plan Indicator for destination address.
    pub dest_addr_npi: NumericPlanIndicator,

    /// 4.1.7 destination_addr: Destination address of this short message. For mobile terminated
    ///       messages, this is the directory number of the recipient MS.
    ///       Max length: 20 octets (21 with null terminator).
    pub destination_addr: DestinationAddr,

    /// 4.1.8 esm_class: Indicates Message Mode and Message Type. The esm_class field is used to
    ///       indicate special message attributes associated with the short message.
    ///       Bits 7..2: Message Mode (00=Default, 01=Datagram, 10=Forward, 11=Store and Forward)
    ///       Bits 1..0: Message Type (00=Default, others vary by mode)
    pub esm_class: u8,

    /// 4.1.9 protocol_id: Protocol Identifier. Network specific field. Set to NULL if not applicable.
    pub protocol_id: u8,

    /// 4.1.10 priority_flag: Designates the priority level of the message.
    ///        Level 0 (lowest) to Level 3 (highest).
    pub priority_flag: PriorityFlag,

    /// 4.1.11 schedule_delivery_time: The short message is to be scheduled by the SMSC for
    ///        delivery. Set to NULL for immediate delivery. Format: YYMMDDhhmmsstnnp
    ///        Max length: 16 octets (17 with null terminator).
    pub schedule_delivery_time: ScheduleDeliveryTime,

    /// 4.1.12 validity_period: The validity period of this message. Set to NULL to request the
    ///        SMSC default validity period. Format same as schedule_delivery_time.
    ///        Max length: 16 octets (17 with null terminator).
    pub validity_period: ValidityPeriod,

    /// 4.1.13 registered_delivery: Indicator to signify if an SMSC delivery receipt, user/manual
    ///        acknowledgment and/or an intermediate notification is required.
    ///        Bit 0-1: MC Delivery Receipt (00=No receipt, 01=Delivery receipt requested)
    ///        Bit 2: SME Manual/User Acknowledgment
    ///        Bit 3: Intermediate Notification
    pub registered_delivery: u8,

    /// 4.1.14 replace_if_present_flag: Flag indicating if the submitted message should replace
    ///        an existing message that has the same source address, destination address and
    ///        message reference. Set to 0 for false, 1 for true.
    pub replace_if_present_flag: u8,

    /// 4.1.15 data_coding: Defines the encoding scheme of the short message user data.
    ///        0x00 = SMSC Default Alphabet (GSM 7-bit default)
    ///        0x01 = IA5 (CCITT T.50)/ASCII
    ///        0x02 = Octet unspecified (8-bit binary)
    ///        0x03 = Latin-1 (ISO-8859-1)
    ///        0x04 = Octet unspecified (8-bit binary)
    ///        0x05 = JIS (X 0208-1990)
    ///        0x06 = Cyrillic (ISO-8859-5)
    ///        0x07 = Latin/Hebrew (ISO-8859-8)
    ///        0x08 = UCS2 (ISO/IEC-10646)
    pub data_coding: u8,

    /// 4.1.16 sm_default_msg_id: Indicates the short message to send from a list of pre-defined
    ///        ('canned') short messages stored on the SMSC. If not using a pre-defined message,
    ///        set to 0.
    pub sm_default_msg_id: u8,

    /// 4.1.17 sm_length: Length in octets of the short_message user data parameter that follows.
    ///        Range: 0 to 254 octets. If sm_length is 0, then the short_message field is not
    ///        present. When sm_length is greater than 0, the short_message field contains
    ///        sm_length octets and should be padded with trailing NULLs if necessary.
    ///        Note: For messages longer than 254 octets, the message_payload optional parameter
    ///        should be used and sm_length should be set to 0.
    pub sm_length: u8,

    /// 4.1.18 short_message: Up to 254 octets of short message user data. The exact physical
    ///        limit for short_message size may vary according to the underlying network.
    ///        Applications which need to send messages longer than 254 octets should use the
    ///        message_payload TLV. When the message_payload TLV is specified, the sm_length
    ///        field should be set to zero.
    pub short_message: ShortMessage,

    // Optional parameters (TLV format)
    /// User Message Reference TLV (0x0204): ESME assigned message reference number.
    pub user_message_reference: Option<Tlv>,

    /// Source Port TLV (0x020A): Indicates the application port number associated with the
    /// source address of the message.
    pub source_port: Option<Tlv>,

    /// Source Address Subunit TLV (0x020B): The subcomponent in the destination device for
    /// which the user data is intended.
    pub source_addr_submit: Option<Tlv>,

    /// Destination Port TLV (0x020C): Indicates the application port number associated with
    /// the destination address of the message.
    pub destination_port: Option<Tlv>,

    /// Destination Address Subunit TLV (0x020D): The subcomponent in the destination device
    /// for which the user data is intended.
    pub dest_addr_submit: Option<Tlv>,

    /// SAR Message Reference Number TLV (0x020E): The reference number for a particular
    /// concatenated short message.
    pub sar_msg_ref_num: Option<Tlv>,

    /// SAR Total Segments TLV (0x020F): Indicates the total number of short messages within
    /// the concatenated short message.
    pub sar_total_segments: Option<Tlv>,

    /// SAR Segment Sequence Number TLV (0x0210): Indicates the sequence number of a particular
    /// short message within the concatenated short message.
    pub sar_segment_seqnum: Option<Tlv>,

    /// More Messages to Send TLV (0x0426): Indicates that there are further messages to follow
    /// for the destination SME.
    pub more_messages_to_send: Option<Tlv>,

    /// Payload Type TLV (0x0019): Defines the type of payload that is being sent in the message.
    pub payload_type: Option<Tlv>,

    /// Message Payload TLV (0x0424): Contains the extended short message user data. Up to 64K
    /// octets can be sent. This TLV must not be specified when the sm_length and short_message
    /// fields contain message data.
    pub message_payload: Option<Tlv>,

    /// Privacy Indicator TLV (0x0201): Indicates the level of privacy associated with the message.
    pub privacy_indicator: Option<Tlv>,

    /// Callback Number TLV (0x0381): A callback number associated with the short message.
    pub callback_num: Option<Tlv>,

    /// Callback Number Presentation Indicator TLV (0x0302): Controls the presentation indication
    /// and screening of the callback number at the mobile station.
    pub callback_num_pres_ind: Option<Tlv>,

    /// Callback Number ATAG TLV (0x0303): Associates an alphanumeric display with the callback number.
    pub callback_num_atag: Option<Tlv>,

    /// Source Subaddress TLV (0x0202): The subaddress of the message originator.
    pub source_subaddress: Option<Tlv>,

    /// Destination Subaddress TLV (0x0203): The subaddress of the message destination.
    pub dest_subaddress: Option<Tlv>,

    /// Display Time TLV (0x1201): Provides the receiving MS with a display time associated with
    /// the message.
    pub display_time: Option<Tlv>,

    /// SMS Signal TLV (0x1203): Indicates the alerting mechanism when the message is received
    /// by the MS.
    pub sms_signal: Option<Tlv>,

    /// MS Validity TLV (0x1204): Indicates the validity period for the message at the MS.
    pub ms_validity: Option<Tlv>,

    /// MS Message Wait Facilities TLV (0x1205): Allows the indication of a message waiting
    /// condition to be set or cleared.
    pub ms_msg_wait_facilities: Option<Tlv>,

    /// Number of Messages TLV (0x0205): Indicates the number of messages stored in a mailbox.
    pub number_of_messages: Option<Tlv>,

    /// Alert on Message Delivery TLV (0x130C): Instructs the MS to alert the user when the
    /// short message is received.
    pub alert_on_msg_delivery: Option<Tlv>,

    /// Language Indicator TLV (0x000D): Indicates the language of the short message.
    pub language_indicator: Option<Tlv>,

    /// ITS Reply Type TLV (0x1380): Indicates the MS user's reply method to an ITS session
    /// setup request.
    pub its_reply_type: Option<Tlv>,

    /// ITS Session Info TLV (0x1383): Session control information for Interactive Teleservice.
    pub its_session_info: Option<Tlv>,

    /// USSD Service Operation TLV (0x0501): Indicates the USSD service operation when
    /// applicable.
    pub ussd_service_op: Option<Tlv>,
}

#[derive(Debug, thiserror::Error)]
pub enum SubmitSmValidationError {
    #[error("sm_length ({sm_length}) does not match short_message length ({message_length})")]
    SmLengthMismatch {
        sm_length: u8,
        message_length: usize,
    },

    #[error("Cannot use both short_message and message_payload - they are mutually exclusive")]
    MutualExclusivityViolation,

    #[error("Fixed array fields are always valid - this error should not occur")]
    FixedArrayError,
}

impl SubmitSm {
    /// Validates the SubmitSm PDU according to SMPP v3.4 specification
    /// Fixed array fields are always valid by construction
    pub fn validate(&self) -> Result<(), SubmitSmValidationError> {
        // Validate sm_length matches actual short_message length
        if self.sm_length as usize != self.short_message.len() as usize {
            return Err(SubmitSmValidationError::SmLengthMismatch {
                sm_length: self.sm_length,
                message_length: self.short_message.len() as usize,
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
    service_type: ServiceType,
    source_addr_ton: TypeOfNumber,
    source_addr_npi: NumericPlanIndicator,
    source_addr: SourceAddr,
    dest_addr_ton: TypeOfNumber,
    dest_addr_npi: NumericPlanIndicator,
    destination_addr: DestinationAddr,
    esm_class: u8,
    protocol_id: u8,
    priority_flag: PriorityFlag,
    schedule_delivery_time: ScheduleDeliveryTime,
    validity_period: ValidityPeriod,
    registered_delivery: u8,
    replace_if_present_flag: u8,
    data_coding: u8,
    sm_default_msg_id: u8,
    short_message: ShortMessage,
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
            service_type: ServiceType::default(),
            source_addr_ton: TypeOfNumber::Unknown,
            source_addr_npi: NumericPlanIndicator::Unknown,
            source_addr: SourceAddr::default(),
            dest_addr_ton: TypeOfNumber::Unknown,
            dest_addr_npi: NumericPlanIndicator::Unknown,
            destination_addr: DestinationAddr::default(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            short_message: ShortMessage::default(),
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

    pub fn service_type(mut self, service_type: &str) -> Self {
        self.service_type = ServiceType::from(service_type);
        self
    }

    pub fn source_addr(mut self, addr: &str) -> Self {
        self.source_addr = SourceAddr::from(addr);
        self
    }

    pub fn destination_addr(mut self, addr: &str) -> Self {
        self.destination_addr = DestinationAddr::from(addr);
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

    pub fn short_message(mut self, message: &str) -> Self {
        self.short_message = ShortMessage::from(message);
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
        self.sm_length = self.short_message.len();

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

/// The submit_sm_resp PDU is used to provide a response to the submit_sm request.
/// The submit_sm_resp PDU body is only returned in the case of a successful submit_sm,
/// i.e., command_status is 0. For unsuccessful submit_sm requests, no submit_sm_resp
/// body is returned, just the PDU header with an appropriate command_status indicating
/// the reason for failure.
#[derive(Clone, Debug, PartialEq)]
pub struct SubmitSmResponse {
    // pub command_length: u32,
    // pub command_id: CommandId::SubmitSmResp,
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Body
    /// 4.2.1 message_id: A unique message identifier assigned by the SMSC to each submitted
    ///       short message. This identifier is returned in the submit_sm_resp and should be
    ///       used in subsequent operations to refer to the message. The message identifier is
    ///       a C-Octet String variable length field up to 65 octets. The format of the
    ///       message_id is vendor specific but must be unique within the SMSC.
    pub message_id: MessageId,
}

impl ToBytes for SubmitSm {
    fn to_bytes(&self) -> Bytes {
        // Fixed arrays are always valid by construction
        self.validate().expect("SubmitSm validation failed");

        let mut buffer = BytesMut::with_capacity(1024);

        // Write junk data that we'll replace later with the actual length
        buffer.put_u32(0_u32);

        buffer.put_u32(CommandId::SubmitSm as u32);
        buffer.put_u32(0u32); // Request PDUs must have command_status = 0 per SMPP spec
        buffer.put_u32(self.sequence_number);

        // Mandatory parameters
        buffer.put(self.service_type.as_ref());
        buffer.put_u8(b'\0');

        buffer.put_u8(self.source_addr_ton as u8);
        buffer.put_u8(self.source_addr_npi as u8);

        buffer.put(self.source_addr.as_ref());
        buffer.put_u8(b'\0');

        buffer.put_u8(self.dest_addr_ton as u8);
        buffer.put_u8(self.dest_addr_npi as u8);

        buffer.put(self.destination_addr.as_ref());
        buffer.put_u8(b'\0');

        buffer.put_u8(self.esm_class);
        buffer.put_u8(self.protocol_id);
        buffer.put_u8(self.priority_flag as u8);

        buffer.put(self.schedule_delivery_time.as_ref());
        buffer.put_u8(b'\0');

        buffer.put(self.validity_period.as_ref());
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
        // Fixed arrays are always valid by construction
        let message_id = self.message_id.as_ref();
        
        let length = 17 + message_id.len();

        let mut buffer = BytesMut::with_capacity(length);

        // Write junk data that we'll replace later with the actual length
        buffer.put_u32(length as u32);

        buffer.put_u32(CommandId::SubmitSmResp as u32);
        buffer.put_u32(self.command_status as u32);
        buffer.put_u32(self.sequence_number);

        buffer.put(message_id);
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
            service_type: ServiceType::default(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: SourceAddr::from("1234567890"),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::from("0987654321"),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 11,
            short_message: ShortMessage::from("Hello World"),
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
            service_type: ServiceType::default(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: SourceAddr::from("1234567890"),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::from("0987654321"),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 11,
            short_message: ShortMessage::from("Hello World"),
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
            message_id: MessageId::from("msg123456789"),
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
            message_id: MessageId::default(),
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
            message_id: MessageId::default(),
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
            service_type: ServiceType::default(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: SourceAddr::from("1234567890"),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::from("0987654321"),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 5, // Wrong length - should be 11
            short_message: ShortMessage::from("Hello World"),
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
    #[should_panic(expected = "String too long for FixedString")]
    fn submit_sm_validation_service_type_too_long() {
        // With fixed arrays, the string length is validated at construction time
        // "TOOLONG" is 7 chars, max for ServiceType is 5
        let _service_type = ServiceType::from("TOOLONG");
    }

    #[test]
    #[should_panic(expected = "String too long for FixedString")]
    fn submit_sm_validation_source_addr_too_long() {
        // With fixed arrays, the string length is validated at construction time
        // 21 chars, max for SourceAddr is 20
        let _source_addr = SourceAddr::from("A".repeat(21).as_str());
    }

    #[test]
    #[should_panic(expected = "Message too long for ShortMessage")]
    fn submit_sm_validation_short_message_too_long() {
        // With fixed arrays, the string length is validated at construction time
        // 255 chars, max for ShortMessage is 254
        let long_message = "A".repeat(255);
        let _short_message = ShortMessage::from(long_message.as_str());
    }

    #[test]
    #[should_panic(expected = "MutualExclusivityViolation")]
    fn submit_sm_validation_mutual_exclusivity() {
        use bytes::Bytes;

        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: ServiceType::default(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: SourceAddr::from("1234567890"),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::from("0987654321"),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 5,
            short_message: ShortMessage::from("Hello"), // Has short message
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
