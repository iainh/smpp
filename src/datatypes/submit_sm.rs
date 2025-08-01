use crate::datatypes::numeric_plan_indicator::NumericPlanIndicator;
use crate::datatypes::priority_flag::PriorityFlag;
use crate::datatypes::tlv::Tlv;
use crate::datatypes::{
    AddressError, CommandId, CommandStatus, DataCoding, DataCodingError, DateTimeError,
    DestinationAddr, EsmClass, EsmClassError, MessageId, ScheduleDeliveryTime, ServiceType,
    ServiceTypeError, ShortMessage, SourceAddr, TypeOfNumber, ValidityPeriod,
};
use bytes::{Buf, BufMut, BytesMut};
use std::io::Cursor;

// Import codec traits
use crate::codec::{CodecError, Decodable, Encodable, PduHeader};
use crate::macros::{builder_setters, encode_optional_tlvs, size_optional_tlvs};

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
    ///       Strongly-typed bitfield that enforces valid mode/type combinations.
    pub esm_class: EsmClass,

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
    ///        Strongly-typed enum that validates encoding schemes and provides character set information.
    pub data_coding: DataCoding,

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

    #[error("Source address format invalid for Type of Number: {0}")]
    SourceAddressError(#[from] AddressError),

    #[error("Destination address format invalid for Type of Number: {0}")]
    DestinationAddressError(AddressError),

    #[error("Service type validation failed: {0}")]
    ServiceTypeError(#[from] ServiceTypeError),

    #[error("Schedule delivery time validation failed: {0}")]
    ScheduleDeliveryTimeError(#[from] DateTimeError),

    #[error("Validity period validation failed: {0}")]
    ValidityPeriodError(DateTimeError),

    #[error("ESM class validation failed: {0}")]
    EsmClassError(#[from] EsmClassError),

    #[error("Data coding validation failed: {0}")]
    DataCodingError(#[from] DataCodingError),

    #[error("Message text incompatible with data coding scheme")]
    MessageTextIncompatible,

    #[error("Fixed array fields are always valid - this error should not occur")]
    FixedArrayError,
}

impl SubmitSm {
    /// Validates the SubmitSm PDU according to SMPP v3.4 specification
    /// Includes validation of strongly-typed fields and protocol-specific rules
    pub fn validate(&self) -> Result<(), SubmitSmValidationError> {
        // Validate sm_length matches actual short_message length
        if self.sm_length as usize != self.short_message.len() as usize {
            return Err(SubmitSmValidationError::SmLengthMismatch {
                sm_length: self.sm_length,
                message_length: self.short_message.len() as usize,
            });
        }

        // Validate mutual exclusivity between short_message and message_payload
        if !self.short_message.is_empty() && self.message_payload.is_some() {
            return Err(SubmitSmValidationError::MutualExclusivityViolation);
        }

        // Validate source address format against its Type of Number
        self.source_addr
            .validate_for_ton(self.source_addr_ton)
            .map_err(SubmitSmValidationError::SourceAddressError)?;

        // Validate destination address format against its Type of Number
        self.destination_addr
            .validate_for_ton(self.dest_addr_ton)
            .map_err(SubmitSmValidationError::DestinationAddressError)?;

        // Validate ESM class structure (mode/type combinations)
        self.esm_class.validate()?;

        // Validate message text compatibility with data coding scheme
        if !self.short_message.is_empty() {
            if let Ok(message_text) = self.short_message.as_str() {
                self.data_coding
                    .validate_text(message_text)
                    .map_err(|_| SubmitSmValidationError::MessageTextIncompatible)?;
            }
        }

        // Note: Service type, schedule delivery time, and validity period are
        // validated at construction time by their respective types

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
    esm_class: EsmClass,
    protocol_id: u8,
    priority_flag: PriorityFlag,
    schedule_delivery_time: ScheduleDeliveryTime,
    validity_period: ValidityPeriod,
    registered_delivery: u8,
    replace_if_present_flag: u8,
    data_coding: DataCoding,
    sm_default_msg_id: u8,
    sm_length: u8,
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
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
            sm_default_msg_id: 0,
            sm_length: 0,
            short_message: ShortMessage::default(),
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

    // Generate simple builder setters using macro
    builder_setters! {
        sequence_number: u32,
        source_addr_ton: TypeOfNumber,
        source_addr_npi: NumericPlanIndicator,
        dest_addr_ton: TypeOfNumber,
        dest_addr_npi: NumericPlanIndicator,
        priority_flag: PriorityFlag,
        registered_delivery: u8,
        esm_class: EsmClass,
        data_coding: DataCoding,
        schedule_delivery_time: ScheduleDeliveryTime,
        validity_period: ValidityPeriod
    }

    // Custom setters that need conversion or special handling
    pub fn service_type(mut self, service_type: &str) -> Self {
        self.service_type = ServiceType::from(service_type);
        self
    }

    pub fn source_addr(mut self, addr: &str) -> Self {
        self.source_addr = SourceAddr::new(addr, TypeOfNumber::Unknown).unwrap_or_default();
        self
    }

    pub fn destination_addr(mut self, addr: &str) -> Self {
        self.destination_addr =
            DestinationAddr::new(addr, TypeOfNumber::Unknown).unwrap_or_default();
        self
    }

    pub fn short_message(mut self, message: &str) -> Self {
        self.short_message = ShortMessage::from(message);
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

// Codec trait implementations for new SMPP codec system
impl Encodable for SubmitSm {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Validate the PDU before encoding
        self.validate().map_err(|e| CodecError::FieldValidation {
            field: "submit_sm",
            reason: e.to_string(),
        })?;

        // Encode PDU header
        let header = PduHeader {
            command_length: 0, // Will be set by the caller
            command_id: CommandId::SubmitSm,
            command_status: self.command_status,
            sequence_number: self.sequence_number,
        };
        header.encode(buf)?;

        // Encode mandatory fields in order
        buf.extend_from_slice(self.service_type.as_ref());
        buf.put_u8(0); // null terminator
        buf.put_u8(self.source_addr_ton as u8);
        buf.put_u8(self.source_addr_npi as u8);
        buf.extend_from_slice(self.source_addr.as_ref());
        buf.put_u8(0); // null terminator
        buf.put_u8(self.dest_addr_ton as u8);
        buf.put_u8(self.dest_addr_npi as u8);
        buf.extend_from_slice(self.destination_addr.as_ref());
        buf.put_u8(0); // null terminator
        buf.put_u8(self.esm_class.into());
        buf.put_u8(self.protocol_id);
        buf.put_u8(self.priority_flag as u8);

        // Schedule delivery time
        buf.extend_from_slice(self.schedule_delivery_time.as_ref());
        buf.put_u8(0); // null terminator

        // Validity period
        buf.extend_from_slice(self.validity_period.as_ref());
        buf.put_u8(0); // null terminator

        buf.put_u8(self.registered_delivery);
        buf.put_u8(self.replace_if_present_flag);
        buf.put_u8(self.data_coding.into());
        buf.put_u8(self.sm_default_msg_id);
        buf.put_u8(self.sm_length);

        // Short message (no null terminator for binary data)
        buf.extend_from_slice(self.short_message.as_bytes());

        // Encode all optional TLV parameters using macro
        encode_optional_tlvs!(
            self,
            buf,
            user_message_reference,
            source_port,
            source_addr_submit,
            destination_port,
            dest_addr_submit,
            sar_msg_ref_num,
            sar_total_segments,
            sar_segment_seqnum,
            more_messages_to_send,
            payload_type,
            message_payload,
            privacy_indicator,
            callback_num,
            callback_num_pres_ind,
            callback_num_atag,
            source_subaddress,
            dest_subaddress,
            display_time,
            sms_signal,
            ms_validity,
            ms_msg_wait_facilities,
            number_of_messages,
            alert_on_msg_delivery,
            language_indicator,
            its_reply_type,
            its_session_info,
            ussd_service_op
        );

        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = PduHeader::SIZE;

        // Mandatory fields
        size += self.service_type.as_ref().len() + 1; // null terminated
        size += 1 + 1; // source_addr_ton + source_addr_npi
        size += self.source_addr.as_ref().len() + 1; // null terminated
        size += 1 + 1; // dest_addr_ton + dest_addr_npi
        size += self.destination_addr.as_ref().len() + 1; // null terminated
        size += 1; // esm_class
        size += 1; // protocol_id
        size += 1; // priority_flag
        size += self.schedule_delivery_time.as_ref().len() + 1; // null terminated
        size += self.validity_period.as_ref().len() + 1; // null terminated
        size += 1; // registered_delivery
        size += 1; // replace_if_present_flag
        size += 1; // data_coding
        size += 1; // sm_default_msg_id
        size += 1; // sm_length
        size += self.short_message.as_bytes().len(); // not null terminated

        // Optional TLV fields - calculate sizes using macro
        size_optional_tlvs!(
            size,
            self,
            user_message_reference,
            source_port,
            source_addr_submit,
            destination_port,
            dest_addr_submit,
            sar_msg_ref_num,
            sar_total_segments,
            sar_segment_seqnum,
            more_messages_to_send,
            payload_type,
            message_payload,
            privacy_indicator,
            callback_num,
            callback_num_pres_ind,
            callback_num_atag,
            source_subaddress,
            dest_subaddress,
            display_time,
            sms_signal,
            ms_validity,
            ms_msg_wait_facilities,
            number_of_messages,
            alert_on_msg_delivery,
            language_indicator,
            its_reply_type,
            its_session_info,
            ussd_service_op
        );

        size
    }
}

impl Decodable for SubmitSm {
    #[allow(clippy::unnecessary_fallible_conversions)]
    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory fields in order

        // service_type (null-terminated string, max 5 chars + null)
        let service_type = Self::read_c_string(buf, 6, "service_type")?;
        let service_type = ServiceType::try_from(service_type.as_str()).map_err(|e| {
            CodecError::FieldValidation {
                field: "service_type",
                reason: e.to_string(),
            }
        })?;

        let source_addr_ton =
            TypeOfNumber::try_from(buf.get_u8()).map_err(|_| CodecError::FieldValidation {
                field: "source_addr_ton",
                reason: "Invalid type of number".to_string(),
            })?;

        let source_addr_npi = NumericPlanIndicator::try_from(buf.get_u8()).map_err(|_| {
            CodecError::FieldValidation {
                field: "source_addr_npi",
                reason: "Invalid numeric plan indicator".to_string(),
            }
        })?;

        // source_addr (null-terminated string, max 20 chars + null)
        let source_addr_str = Self::read_c_string(buf, 21, "source_addr")?;
        let source_addr = SourceAddr::new(&source_addr_str, source_addr_ton).map_err(|e| {
            CodecError::FieldValidation {
                field: "source_addr",
                reason: e.to_string(),
            }
        })?;

        let dest_addr_ton =
            TypeOfNumber::try_from(buf.get_u8()).map_err(|_| CodecError::FieldValidation {
                field: "dest_addr_ton",
                reason: "Invalid type of number".to_string(),
            })?;

        let dest_addr_npi = NumericPlanIndicator::try_from(buf.get_u8()).map_err(|_| {
            CodecError::FieldValidation {
                field: "dest_addr_npi",
                reason: "Invalid numeric plan indicator".to_string(),
            }
        })?;

        // destination_addr (null-terminated string, max 20 chars + null)
        let dest_addr_str = Self::read_c_string(buf, 21, "destination_addr")?;
        let destination_addr =
            DestinationAddr::new(&dest_addr_str, dest_addr_ton).map_err(|e| {
                CodecError::FieldValidation {
                    field: "destination_addr",
                    reason: e.to_string(),
                }
            })?;

        let esm_class = EsmClass::from(buf.get_u8());

        let protocol_id = buf.get_u8();

        let priority_flag =
            PriorityFlag::try_from(buf.get_u8()).map_err(|_| CodecError::FieldValidation {
                field: "priority_flag",
                reason: "Invalid priority flag".to_string(),
            })?;

        // schedule_delivery_time (null-terminated string, max 16 chars + null)
        let schedule_time_str = Self::read_c_string(buf, 17, "schedule_delivery_time")?;
        let schedule_delivery_time = ScheduleDeliveryTime::try_from(schedule_time_str.as_str())
            .map_err(|e| CodecError::FieldValidation {
                field: "schedule_delivery_time",
                reason: e.to_string(),
            })?;

        // validity_period (null-terminated string, max 16 chars + null)
        let validity_str = Self::read_c_string(buf, 17, "validity_period")?;
        let validity_period = ValidityPeriod::from(validity_str.as_str());

        let registered_delivery = buf.get_u8();
        let replace_if_present_flag = buf.get_u8();

        let data_coding = DataCoding::from(buf.get_u8());

        let sm_default_msg_id = buf.get_u8();
        let sm_length = buf.get_u8();

        // short_message (binary data, not null-terminated)
        if buf.remaining() < sm_length as usize {
            return Err(CodecError::Incomplete);
        }
        let mut short_message_bytes = vec![0u8; sm_length as usize];
        buf.copy_to_slice(&mut short_message_bytes);
        let short_message =
            ShortMessage::new(&short_message_bytes).map_err(|e| CodecError::FieldValidation {
                field: "short_message",
                reason: e.to_string(),
            })?;

        // Parse optional TLV parameters
        let mut tlvs = std::collections::HashMap::new();
        while buf.remaining() >= 4 {
            let tlv = Tlv::decode(buf)?;
            tlvs.insert(tlv.tag, tlv);
        }

        // Extract specific TLVs
        let user_message_reference = tlvs.remove(&0x0204);
        let source_port = tlvs.remove(&0x020A);
        let source_addr_submit = tlvs.remove(&0x020B);
        let destination_port = tlvs.remove(&0x020C);
        let dest_addr_submit = tlvs.remove(&0x020D);
        let sar_msg_ref_num = tlvs.remove(&0x020E);
        let sar_total_segments = tlvs.remove(&0x020F);
        let sar_segment_seqnum = tlvs.remove(&0x0210);
        let more_messages_to_send = tlvs.remove(&0x0426);
        let payload_type = tlvs.remove(&0x0019);
        let message_payload = tlvs.remove(&0x0424);
        let privacy_indicator = tlvs.remove(&0x0201);
        let callback_num = tlvs.remove(&0x0381);
        let callback_num_pres_ind = tlvs.remove(&0x0302);
        let callback_num_atag = tlvs.remove(&0x0303);
        let source_subaddress = tlvs.remove(&0x0202);
        let dest_subaddress = tlvs.remove(&0x0203);
        let display_time = tlvs.remove(&0x1201);
        let sms_signal = tlvs.remove(&0x1203);
        let ms_validity = tlvs.remove(&0x1204);
        let ms_msg_wait_facilities = tlvs.remove(&0x1205);
        let number_of_messages = tlvs.remove(&0x0205);
        let alert_on_msg_delivery = tlvs.remove(&0x130C);
        let language_indicator = tlvs.remove(&0x000D);
        let its_reply_type = tlvs.remove(&0x1380);
        let its_session_info = tlvs.remove(&0x1383);
        let ussd_service_op = tlvs.remove(&0x0501);

        let submit_sm = Self {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            service_type,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            dest_addr_ton,
            dest_addr_npi,
            destination_addr,
            esm_class,
            protocol_id,
            priority_flag,
            schedule_delivery_time,
            validity_period,
            registered_delivery,
            replace_if_present_flag,
            data_coding,
            sm_default_msg_id,
            sm_length,
            short_message,
            user_message_reference,
            source_port,
            source_addr_submit,
            destination_port,
            dest_addr_submit,
            sar_msg_ref_num,
            sar_total_segments,
            sar_segment_seqnum,
            more_messages_to_send,
            payload_type,
            message_payload,
            privacy_indicator,
            callback_num,
            callback_num_pres_ind,
            callback_num_atag,
            source_subaddress,
            dest_subaddress,
            display_time,
            sms_signal,
            ms_validity,
            ms_msg_wait_facilities,
            number_of_messages,
            alert_on_msg_delivery,
            language_indicator,
            its_reply_type,
            its_session_info,
            ussd_service_op,
        };

        // Validate the decoded PDU
        submit_sm
            .validate()
            .map_err(|e| CodecError::FieldValidation {
                field: "submit_sm",
                reason: e.to_string(),
            })?;

        Ok(submit_sm)
    }

    fn command_id() -> CommandId {
        CommandId::SubmitSm
    }
}

impl SubmitSm {
    /// Helper function to read null-terminated C strings with length limits
    fn read_c_string(
        buf: &mut Cursor<&[u8]>,
        max_len: usize,
        field_name: &'static str,
    ) -> Result<String, CodecError> {
        let mut string_bytes = Vec::new();
        let mut bytes_read = 0;

        while bytes_read < max_len {
            if buf.remaining() == 0 {
                return Err(CodecError::Incomplete);
            }

            let byte = buf.get_u8();
            bytes_read += 1;

            if byte == 0 {
                // Found null terminator
                break;
            }

            string_bytes.push(byte);
        }

        String::from_utf8(string_bytes).map_err(|e| CodecError::Utf8Error {
            field: field_name,
            source: e,
        })
    }
}

// Also implement codec for SubmitSmResponse
impl Encodable for SubmitSmResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Encode PDU header
        let header = PduHeader {
            command_length: 0, // Will be set by the caller
            command_id: CommandId::SubmitSmResp,
            command_status: self.command_status,
            sequence_number: self.sequence_number,
        };
        header.encode(buf)?;

        // Encode message_id (null-terminated string)
        buf.extend_from_slice(self.message_id.as_ref());
        buf.put_u8(0); // null terminator

        Ok(())
    }

    fn encoded_size(&self) -> usize {
        PduHeader::SIZE + self.message_id.as_ref().len() + 1 // +1 for null terminator
    }
}

impl Decodable for SubmitSmResponse {
    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // message_id (null-terminated string, max 64 chars + null)
        let message_id_str = Self::read_c_string(buf, 65, "message_id")?;
        let message_id = MessageId::from(message_id_str.as_str());

        Ok(Self {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            message_id,
        })
    }

    fn command_id() -> CommandId {
        CommandId::SubmitSmResp
    }
}

impl SubmitSmResponse {
    /// Helper function to read null-terminated C strings with length limits
    fn read_c_string(
        buf: &mut Cursor<&[u8]>,
        max_len: usize,
        field_name: &'static str,
    ) -> Result<String, CodecError> {
        let mut string_bytes = Vec::new();
        let mut bytes_read = 0;

        while bytes_read < max_len {
            if buf.remaining() == 0 {
                return Err(CodecError::Incomplete);
            }

            let byte = buf.get_u8();
            bytes_read += 1;

            if byte == 0 {
                // Found null terminator
                break;
            }

            string_bytes.push(byte);
        }

        String::from_utf8(string_bytes).map_err(|e| CodecError::Utf8Error {
            field: field_name,
            source: e,
        })
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
            source_addr: SourceAddr::new("1234567890", TypeOfNumber::International).unwrap(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::new("0987654321", TypeOfNumber::International)
                .unwrap(),
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
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
        assert!(
            bytes
                .windows(message_bytes.len())
                .any(|window| window == message_bytes)
        );
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
            source_addr: SourceAddr::new("1234567890", TypeOfNumber::International).unwrap(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::new("0987654321", TypeOfNumber::International)
                .unwrap(),
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
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

        assert!(
            bytes
                .windows(tlv1_bytes.len())
                .any(|window| window == tlv1_bytes)
        );
        assert!(
            bytes
                .windows(tlv2_bytes.len())
                .any(|window| window == tlv2_bytes)
        );
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
    #[should_panic(expected = "sm_length (5) does not match short_message length (11)")]
    fn submit_sm_validation_sm_length_mismatch() {
        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: ServiceType::default(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: SourceAddr::new("1234567890", TypeOfNumber::International).unwrap(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::new("0987654321", TypeOfNumber::International)
                .unwrap(),
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
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
    #[should_panic(expected = "Invalid service type format")]
    fn submit_sm_validation_service_type_too_long() {
        // With strongly-typed ServiceType, length validation returns Result with specific error
        // "TOOLONG" is 7 chars, max for ServiceType is 5
        let _service_type = ServiceType::from("TOOLONG");
    }

    #[test]
    fn submit_sm_validation_source_addr_too_long() {
        // With strongly-typed addresses, length validation returns Result instead of panicking
        // 21 chars is too long for SourceAddr (max 20)
        let result = SourceAddr::new(&"A".repeat(21), TypeOfNumber::Unknown);
        assert!(result.is_err());
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
    #[should_panic(
        expected = "Cannot use both short_message and message_payload - they are mutually exclusive"
    )]
    fn submit_sm_validation_mutual_exclusivity() {
        use bytes::Bytes;

        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: ServiceType::default(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: SourceAddr::new("1234567890", TypeOfNumber::International).unwrap(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::new("0987654321", TypeOfNumber::International)
                .unwrap(),
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
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
