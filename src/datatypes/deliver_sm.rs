use crate::codec::{CodecError, Encodable, PduHeader, encode_cstring, encode_u8};
use crate::datatypes::numeric_plan_indicator::NumericPlanIndicator;
use crate::datatypes::tlv::Tlv;
use crate::datatypes::{
    CommandId, CommandStatus, DataCoding, DestinationAddr, EsmClass, MessageId,
    ScheduleDeliveryTime, ServiceType, ShortMessage, SourceAddr, TypeOfNumber, ValidityPeriod,
};
use bytes::BytesMut;

/// This operation is used by the SMSC to deliver a short message to an ESME.
/// The deliver_sm PDU is used to deliver both mobile originated messages and
/// delivery receipts from the SMSC to the ESME.
#[derive(Clone, Debug, PartialEq)]
pub struct DeliverSm {
    // pub command_length: u32,
    // pub command_id: CommandId::DeliverSm,
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Mandatory parameters
    /// 4.3.1 service_type: The service_type parameter can be used to indicate the SMS
    ///       Application service associated with the message. Set to NULL if not applicable.
    ///       Max length: 5 octets (6 with null terminator).
    pub service_type: ServiceType,

    /// 4.3.2 source_addr_ton: Type of Number for source address.
    pub source_addr_ton: TypeOfNumber,

    /// 4.3.3 source_addr_npi: Numbering Plan Indicator for source address.
    pub source_addr_npi: NumericPlanIndicator,

    /// 4.3.4 source_addr: Address of SME which originated this message.
    ///       Max length: 20 octets (21 with null terminator).
    pub source_addr: SourceAddr,

    /// 4.3.5 dest_addr_ton: Type of Number for destination address.
    pub dest_addr_ton: TypeOfNumber,

    /// 4.3.6 dest_addr_npi: Numbering Plan Indicator for destination address.
    pub dest_addr_npi: NumericPlanIndicator,

    /// 4.3.7 destination_addr: Destination address of this short message.
    ///       Max length: 20 octets (21 with null terminator).
    pub destination_addr: DestinationAddr,

    /// 4.3.8 esm_class: Indicates Message Mode and Message Type. Used to indicate
    ///       special message attributes associated with the short message.
    ///       Strongly-typed bitfield that enforces valid mode/type combinations.
    pub esm_class: EsmClass,

    /// 4.3.9 protocol_id: Protocol Identifier. Network specific field.
    pub protocol_id: u8,

    /// 4.3.10 priority_flag: Designates the priority level of the message.
    ///        Level 0 (lowest) to Level 3 (highest).
    pub priority_flag: u8,

    /// 4.3.11 schedule_delivery_time: Not used for deliver_sm. Set to NULL.
    pub schedule_delivery_time: ScheduleDeliveryTime,

    /// 4.3.12 validity_period: Not used for deliver_sm. Set to NULL.
    pub validity_period: ValidityPeriod,

    /// 4.3.13 registered_delivery: Indicator to signify if a delivery receipt or
    ///        acknowledgment is required.
    pub registered_delivery: u8,

    /// 4.3.14 replace_if_present_flag: Not used for deliver_sm. Set to 0.
    pub replace_if_present_flag: u8,

    /// 4.3.15 data_coding: Defines the encoding scheme of the short message user data.
    ///        Strongly-typed enum that validates encoding schemes and provides character set information.
    pub data_coding: DataCoding,

    /// 4.3.16 sm_default_msg_id: Not used for deliver_sm. Set to 0.
    pub sm_default_msg_id: u8,

    /// 4.3.17 sm_length: Length in octets of the short_message user data parameter.
    ///        Range: 0 to 254 octets. If sm_length is 0, then the short_message
    ///        field is not present.
    pub sm_length: u8,

    /// 4.3.18 short_message: Up to 254 octets of short message user data.
    ///        For delivery receipts, this field contains the delivery receipt data.
    pub short_message: ShortMessage,

    // Optional parameters (TLV format)
    /// User Message Reference TLV (0x0204): ESME assigned message reference number.
    pub user_message_reference: Option<Tlv>,

    /// Source Port TLV (0x020A): Indicates the application port number associated with the
    /// source address of the message.
    pub source_port: Option<Tlv>,

    /// Destination Port TLV (0x020C): Indicates the application port number associated with
    /// the destination address of the message.
    pub destination_port: Option<Tlv>,

    /// SAR Message Reference Number TLV (0x020E): The reference number for a particular
    /// concatenated short message.
    pub sar_msg_ref_num: Option<Tlv>,

    /// SAR Total Segments TLV (0x020F): Indicates the total number of short messages within
    /// the concatenated short message.
    pub sar_total_segments: Option<Tlv>,

    /// SAR Segment Sequence Number TLV (0x0210): Indicates the sequence number of a particular
    /// short message within the concatenated short message.
    pub sar_segment_seqnum: Option<Tlv>,

    /// User Data Header TLV (0x0005): User Data Header for advanced messaging features.
    pub user_data_header: Option<Tlv>,

    /// Privacy Indicator TLV (0x0201): Indicates the level of privacy associated with the message.
    pub privacy_indicator: Option<Tlv>,

    /// Callback Number TLV (0x0381): A callback number associated with the short message.
    pub callback_num: Option<Tlv>,

    /// Source Subaddress TLV (0x0202): The subaddress of the message originator.
    pub source_subaddress: Option<Tlv>,

    /// Destination Subaddress TLV (0x0203): The subaddress of the message destination.
    pub dest_subaddress: Option<Tlv>,

    /// Language Indicator TLV (0x000D): Indicates the language of the short message.
    pub language_indicator: Option<Tlv>,

    /// ITS Session Info TLV (0x1383): Session control information for Interactive Teleservice.
    pub its_session_info: Option<Tlv>,

    /// Network Error Code TLV (0x0423): Used to indicate the actual network error code
    /// for an unsuccessful message delivery.
    pub network_error_code: Option<Tlv>,

    /// Message Payload TLV (0x0424): Contains the extended short message user data.
    /// This TLV must not be specified when the sm_length and short_message fields contain data.
    pub message_payload: Option<Tlv>,

    /// Delivery Failure Reason TLV (0x0425): Used in delivery receipts to indicate the
    /// reason for message delivery failure.
    pub delivery_failure_reason: Option<Tlv>,

    /// Additional Status Info Text TLV (0x001D): ASCII text giving a description of the
    /// status of a message delivery.
    pub additional_status_info_text: Option<Tlv>,

    /// DPFR Result TLV (0x0420): Data Packet Fragmentation and Reassembly result.
    pub dpf_result: Option<Tlv>,

    /// Set DPF TLV (0x0421): Requests the SMSC to set a specific DPF at the MS.
    pub set_dpf: Option<Tlv>,

    /// MS Availability Status TLV (0x0422): Used to indicate the availability state
    /// of the requested destination mobile station.
    pub ms_availability_status: Option<Tlv>,

    /// Receipted Message ID TLV (0x001E): The message identifier of the message being receipted.
    /// Used in delivery receipts.
    pub receipted_message_id: Option<Tlv>,

    /// Message State TLV (0x0427): The state of the message at the time the receipt was generated.
    /// Used in delivery receipts.
    pub message_state: Option<Tlv>,
}

#[derive(Debug, thiserror::Error)]
pub enum DeliverSmValidationError {
    #[error("sm_length ({sm_length}) does not match short_message length ({message_length})")]
    SmLengthMismatch {
        sm_length: u8,
        message_length: usize,
    },

    #[error("Cannot use both short_message and message_payload - they are mutually exclusive")]
    MutualExclusivityViolation,
}

impl DeliverSm {
    /// Validates the DeliverSm PDU according to SMPP v3.4 specification
    /// Fixed array fields are always valid by construction
    pub fn validate(&self) -> Result<(), DeliverSmValidationError> {
        // Validate sm_length matches actual short_message length
        if self.sm_length as usize != self.short_message.len() as usize {
            return Err(DeliverSmValidationError::SmLengthMismatch {
                sm_length: self.sm_length,
                message_length: self.short_message.len() as usize,
            });
        }

        // Validate mutual exclusivity
        if !self.short_message.is_empty() && self.message_payload.is_some() {
            return Err(DeliverSmValidationError::MutualExclusivityViolation);
        }

        Ok(())
    }

    /// Creates a builder for constructing DeliverSm PDUs with validation
    pub fn builder() -> DeliverSmBuilder {
        DeliverSmBuilder::new()
    }
}

/// Builder for creating DeliverSm PDUs with validation and sensible defaults
pub struct DeliverSmBuilder {
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
    priority_flag: u8,
    schedule_delivery_time: ScheduleDeliveryTime,
    validity_period: ValidityPeriod,
    registered_delivery: u8,
    replace_if_present_flag: u8,
    data_coding: DataCoding,
    sm_default_msg_id: u8,
    short_message: ShortMessage,
    // Optional TLVs
    user_message_reference: Option<Tlv>,
    source_port: Option<Tlv>,
    destination_port: Option<Tlv>,
    sar_msg_ref_num: Option<Tlv>,
    sar_total_segments: Option<Tlv>,
    sar_segment_seqnum: Option<Tlv>,
    user_data_header: Option<Tlv>,
    privacy_indicator: Option<Tlv>,
    callback_num: Option<Tlv>,
    source_subaddress: Option<Tlv>,
    dest_subaddress: Option<Tlv>,
    language_indicator: Option<Tlv>,
    its_session_info: Option<Tlv>,
    network_error_code: Option<Tlv>,
    message_payload: Option<Tlv>,
    delivery_failure_reason: Option<Tlv>,
    additional_status_info_text: Option<Tlv>,
    dpf_result: Option<Tlv>,
    set_dpf: Option<Tlv>,
    ms_availability_status: Option<Tlv>,
    receipted_message_id: Option<Tlv>,
    message_state: Option<Tlv>,
    sm_length: u8,
}

impl Default for DeliverSmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DeliverSmBuilder {
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
            priority_flag: 0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
            sm_default_msg_id: 0,
            short_message: ShortMessage::default(),
            sm_length: 0,
            user_message_reference: None,
            source_port: None,
            destination_port: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            user_data_header: None,
            privacy_indicator: None,
            callback_num: None,
            source_subaddress: None,
            dest_subaddress: None,
            language_indicator: None,
            its_session_info: None,
            network_error_code: None,
            message_payload: None,
            delivery_failure_reason: None,
            additional_status_info_text: None,
            dpf_result: None,
            set_dpf: None,
            ms_availability_status: None,
            receipted_message_id: None,
            message_state: None,
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
        self.source_addr = SourceAddr::new(addr, TypeOfNumber::Unknown).unwrap_or_default();
        self
    }

    pub fn destination_addr(mut self, addr: &str) -> Self {
        self.destination_addr =
            DestinationAddr::new(addr, TypeOfNumber::Unknown).unwrap_or_default();
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

    pub fn esm_class(mut self, esm_class: EsmClass) -> Self {
        self.esm_class = esm_class;
        self
    }

    pub fn data_coding(mut self, data_coding: DataCoding) -> Self {
        self.data_coding = data_coding;
        self
    }

    pub fn receipted_message_id(mut self, tlv: Tlv) -> Self {
        self.receipted_message_id = Some(tlv);
        self
    }

    pub fn message_state(mut self, tlv: Tlv) -> Self {
        self.message_state = Some(tlv);
        self
    }

    pub fn message_payload(mut self, tlv: Tlv) -> Self {
        self.message_payload = Some(tlv);
        self
    }

    /// Build the DeliverSm, performing validation and calculating sm_length automatically
    pub fn build(mut self) -> Result<DeliverSm, DeliverSmValidationError> {
        // Auto-calculate sm_length from short_message
        self.sm_length = self.short_message.len();

        let deliver_sm = DeliverSm {
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
            destination_port: self.destination_port,
            sar_msg_ref_num: self.sar_msg_ref_num,
            sar_total_segments: self.sar_total_segments,
            sar_segment_seqnum: self.sar_segment_seqnum,
            user_data_header: self.user_data_header,
            privacy_indicator: self.privacy_indicator,
            callback_num: self.callback_num,
            source_subaddress: self.source_subaddress,
            dest_subaddress: self.dest_subaddress,
            language_indicator: self.language_indicator,
            its_session_info: self.its_session_info,
            network_error_code: self.network_error_code,
            message_payload: self.message_payload,
            delivery_failure_reason: self.delivery_failure_reason,
            additional_status_info_text: self.additional_status_info_text,
            dpf_result: self.dpf_result,
            set_dpf: self.set_dpf,
            ms_availability_status: self.ms_availability_status,
            receipted_message_id: self.receipted_message_id,
            message_state: self.message_state,
        };

        // Validate before returning
        deliver_sm.validate()?;
        Ok(deliver_sm)
    }
}

/// The deliver_sm_resp PDU is used to provide a response to the deliver_sm request.
#[derive(Clone, Debug, PartialEq)]
pub struct DeliverSmResponse {
    // pub command_length: u32,
    // pub command_id: CommandId::DeliverSmResp,
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Body
    /// 4.4.1 message_id: Set to NULL. Not used for deliver_sm_resp.
    pub message_id: MessageId,
}

// New codec trait implementations

impl Encodable for DeliverSm {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Validate the PDU before encoding
        self.validate().map_err(|e| CodecError::FieldValidation {
            field: "deliver_sm",
            reason: e.to_string(),
        })?;

        // Encode PDU header
        let header = PduHeader {
            command_length: 0, // Will be set by the caller
            command_id: CommandId::DeliverSm,
            command_status: self.command_status,
            sequence_number: self.sequence_number,
        };
        header.encode(buf)?;

        // Encode mandatory parameters as fixed-length fields
        encode_cstring(buf, self.service_type.as_str(), 6);
        encode_u8(buf, self.source_addr_ton as u8);
        encode_u8(buf, self.source_addr_npi as u8);
        encode_cstring(buf, self.source_addr.as_str().unwrap_or(""), 21);
        encode_u8(buf, self.dest_addr_ton as u8);
        encode_u8(buf, self.dest_addr_npi as u8);
        encode_cstring(buf, self.destination_addr.as_str().unwrap_or(""), 21);
        encode_u8(buf, self.esm_class.to_byte());
        encode_u8(buf, self.protocol_id);
        encode_u8(buf, self.priority_flag);
        encode_cstring(buf, self.schedule_delivery_time.as_str().unwrap_or(""), 17);
        encode_cstring(buf, self.validity_period.as_str().unwrap_or(""), 17);
        encode_u8(buf, self.registered_delivery);
        encode_u8(buf, self.replace_if_present_flag);
        encode_u8(buf, self.data_coding.to_byte());
        encode_u8(buf, self.sm_default_msg_id);
        encode_u8(buf, self.sm_length);

        // Encode short_message (variable length up to sm_length)
        let message_bytes = self.short_message.as_bytes();
        buf.extend_from_slice(&message_bytes[..(self.sm_length as usize).min(message_bytes.len())]);

        // Encode optional TLV parameters
        if let Some(ref tlv) = self.user_message_reference {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.source_port {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.destination_port {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.sar_msg_ref_num {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.sar_total_segments {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.sar_segment_seqnum {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.user_data_header {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.privacy_indicator {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.callback_num {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.source_subaddress {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.dest_subaddress {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.language_indicator {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.its_session_info {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.network_error_code {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.message_payload {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.delivery_failure_reason {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.additional_status_info_text {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.dpf_result {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.set_dpf {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.ms_availability_status {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.receipted_message_id {
            tlv.encode(buf)?;
        }
        if let Some(ref tlv) = self.message_state {
            tlv.encode(buf)?;
        }

        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = PduHeader::SIZE;

        // Fixed mandatory fields
        size += 6 + 1 + 1 + 21 + 1 + 1 + 21 + 1 + 1 + 1 + 17 + 17 + 1 + 1 + 1 + 1 + 1;

        // Variable short_message length
        size += self.sm_length as usize;

        // Optional TLV parameters
        if let Some(ref tlv) = self.user_message_reference {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.source_port {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.destination_port {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.sar_msg_ref_num {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.sar_total_segments {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.sar_segment_seqnum {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.user_data_header {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.privacy_indicator {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.callback_num {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.source_subaddress {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.dest_subaddress {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.language_indicator {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.its_session_info {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.network_error_code {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.message_payload {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.delivery_failure_reason {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.additional_status_info_text {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.dpf_result {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.set_dpf {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.ms_availability_status {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.receipted_message_id {
            size += tlv.encoded_size();
        }
        if let Some(ref tlv) = self.message_state {
            size += tlv.encoded_size();
        }

        size
    }
}

impl Encodable for DeliverSmResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Encode PDU header
        let header = PduHeader {
            command_length: 0, // Will be set by the caller
            command_id: CommandId::DeliverSmResp,
            command_status: self.command_status,
            sequence_number: self.sequence_number,
        };
        header.encode(buf)?;

        // Encode body - message_id as null-terminated string
        encode_cstring(buf, self.message_id.as_str().unwrap_or(""), 65); // Max MessageId length

        Ok(())
    }

    fn encoded_size(&self) -> usize {
        PduHeader::SIZE + 65 // header + fixed MessageId field size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliver_sm_to_bytes_basic() {
        let deliver_sm = DeliverSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: ServiceType::from(""),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: SourceAddr::new("1234567890", TypeOfNumber::International).unwrap(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::new("0987654321", TypeOfNumber::International)
                .unwrap(),
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: 0,
            schedule_delivery_time: ScheduleDeliveryTime::from(""),
            validity_period: ValidityPeriod::from(""),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
            sm_default_msg_id: 0,
            sm_length: 11,
            short_message: ShortMessage::from("Hello World"),
            user_message_reference: None,
            source_port: None,
            destination_port: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            user_data_header: None,
            privacy_indicator: None,
            callback_num: None,
            source_subaddress: None,
            dest_subaddress: None,
            language_indicator: None,
            its_session_info: None,
            network_error_code: None,
            message_payload: None,
            delivery_failure_reason: None,
            additional_status_info_text: None,
            dpf_result: None,
            set_dpf: None,
            ms_availability_status: None,
            receipted_message_id: None,
            message_state: None,
        };

        let bytes = deliver_sm.to_bytes();

        // Verify header
        assert_eq!(&bytes[0..4], &(bytes.len() as u32).to_be_bytes()); // command_length
        assert_eq!(&bytes[4..8], &(CommandId::DeliverSm as u32).to_be_bytes()); // command_id
        assert_eq!(&bytes[8..12], &(CommandStatus::Ok as u32).to_be_bytes()); // command_status
        assert_eq!(&bytes[12..16], &1u32.to_be_bytes()); // sequence_number

        // Check that short message is included
        let message_bytes = "Hello World".as_bytes();
        assert!(
            bytes
                .windows(message_bytes.len())
                .any(|window| window == message_bytes)
        );
    }

    #[test]
    fn deliver_sm_builder_basic() {
        let deliver_sm = DeliverSm::builder()
            .source_addr("1234567890")
            .destination_addr("0987654321")
            .short_message("Test message")
            .build()
            .unwrap();

        assert_eq!(deliver_sm.source_addr, "1234567890");
        assert_eq!(deliver_sm.destination_addr, "0987654321");
        assert_eq!(deliver_sm.short_message.as_str().unwrap(), "Test message");
        assert_eq!(deliver_sm.sm_length, 12); // Length of "Test message"
    }

    #[test]
    fn deliver_sm_delivery_receipt() {
        let receipt_message = "id:1234567890 sub:001 dlvrd:001 submit date:2201011200 done date:2201011205 stat:DELIVRD err:000 text:Hello";

        let deliver_sm = DeliverSm::builder()
            .source_addr("1234567890")
            .destination_addr("0987654321")
            .esm_class(EsmClass::from(0x04)) // Delivery receipt
            .short_message(receipt_message)
            .build()
            .unwrap();

        assert_eq!(deliver_sm.esm_class, EsmClass::from(0x04));
        assert_eq!(deliver_sm.short_message.as_str().unwrap(), receipt_message);
        assert_eq!(deliver_sm.sm_length, receipt_message.len() as u8);
    }

    #[test]
    fn deliver_sm_response_to_bytes() {
        let deliver_sm_response = DeliverSmResponse {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            message_id: MessageId::from(""), // Usually NULL for deliver_sm_resp
        };

        let bytes = Encodable::to_bytes(&deliver_sm_response);

        // Verify header
        assert_eq!(&bytes[0..4], &(bytes.len() as u32).to_be_bytes()); // command_length
        assert_eq!(
            &bytes[4..8],
            &(CommandId::DeliverSmResp as u32).to_be_bytes()
        ); // command_id
        assert_eq!(&bytes[8..12], &(CommandStatus::Ok as u32).to_be_bytes()); // command_status
        assert_eq!(&bytes[12..16], &1u32.to_be_bytes()); // sequence_number

        // Should be SMPP v3.4 fixed size: 16 bytes header + 65 bytes MessageId field
        assert_eq!(bytes.len(), 81);
        assert_eq!(bytes[16], 0); // null terminator for empty message_id
    }

    #[test]
    #[should_panic(expected = "sm_length (5) does not match short_message length (11)")]
    fn deliver_sm_validation_sm_length_mismatch() {
        let deliver_sm = DeliverSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: ServiceType::from(""),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: SourceAddr::new("1234567890", TypeOfNumber::International).unwrap(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::new("0987654321", TypeOfNumber::International)
                .unwrap(),
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: 0,
            schedule_delivery_time: ScheduleDeliveryTime::from(""),
            validity_period: ValidityPeriod::from(""),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
            sm_default_msg_id: 0,
            sm_length: 5, // Wrong length - should be 11
            short_message: ShortMessage::from("Hello World"),
            user_message_reference: None,
            source_port: None,
            destination_port: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            user_data_header: None,
            privacy_indicator: None,
            callback_num: None,
            source_subaddress: None,
            dest_subaddress: None,
            language_indicator: None,
            its_session_info: None,
            network_error_code: None,
            message_payload: None,
            delivery_failure_reason: None,
            additional_status_info_text: None,
            dpf_result: None,
            set_dpf: None,
            ms_availability_status: None,
            receipted_message_id: None,
            message_state: None,
        };

        let _ = deliver_sm.to_bytes(); // Should panic
    }
}
