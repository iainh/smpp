use crate::datatypes::numeric_plan_indicator::NumericPlanIndicator;
use crate::datatypes::tlv::Tlv;
use crate::datatypes::{CommandId, CommandStatus, ToBytes, TypeOfNumber};
use bytes::{BufMut, Bytes, BytesMut};

// SMPP v3.4 specification field length limits (excluding null terminator)
const MAX_SERVICE_TYPE_LENGTH: usize = 5;
const MAX_SOURCE_ADDR_LENGTH: usize = 20;
const MAX_DESTINATION_ADDR_LENGTH: usize = 20;
const MAX_SHORT_MESSAGE_LENGTH: usize = 254;

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
    pub service_type: String,

    /// 4.3.2 source_addr_ton: Type of Number for source address.
    pub source_addr_ton: TypeOfNumber,

    /// 4.3.3 source_addr_npi: Numbering Plan Indicator for source address.
    pub source_addr_npi: NumericPlanIndicator,

    /// 4.3.4 source_addr: Address of SME which originated this message.
    ///       Max length: 20 octets (21 with null terminator).
    pub source_addr: String,

    /// 4.3.5 dest_addr_ton: Type of Number for destination address.
    pub dest_addr_ton: TypeOfNumber,

    /// 4.3.6 dest_addr_npi: Numbering Plan Indicator for destination address.
    pub dest_addr_npi: NumericPlanIndicator,

    /// 4.3.7 destination_addr: Destination address of this short message.
    ///       Max length: 20 octets (21 with null terminator).
    pub destination_addr: String,

    /// 4.3.8 esm_class: Indicates Message Mode and Message Type. Used to indicate
    ///       special message attributes associated with the short message.
    ///       Bit 2: Message Type (0=Default/Normal, 1=Delivery Receipt)
    ///       Bits 7..3: Message Mode
    pub esm_class: u8,

    /// 4.3.9 protocol_id: Protocol Identifier. Network specific field.
    pub protocol_id: u8,

    /// 4.3.10 priority_flag: Designates the priority level of the message.
    ///        Level 0 (lowest) to Level 3 (highest).
    pub priority_flag: u8,

    /// 4.3.11 schedule_delivery_time: Not used for deliver_sm. Set to NULL.
    pub schedule_delivery_time: String,

    /// 4.3.12 validity_period: Not used for deliver_sm. Set to NULL.
    pub validity_period: String,

    /// 4.3.13 registered_delivery: Indicator to signify if a delivery receipt or
    ///        acknowledgment is required.
    pub registered_delivery: u8,

    /// 4.3.14 replace_if_present_flag: Not used for deliver_sm. Set to 0.
    pub replace_if_present_flag: u8,

    /// 4.3.15 data_coding: Defines the encoding scheme of the short message user data.
    ///        0x00 = SMSC Default Alphabet (GSM 7-bit default)
    ///        0x01 = IA5 (CCITT T.50)/ASCII
    ///        0x02 = Octet unspecified (8-bit binary)
    ///        0x03 = Latin-1 (ISO-8859-1)
    ///        0x08 = UCS2 (ISO/IEC-10646)
    pub data_coding: u8,

    /// 4.3.16 sm_default_msg_id: Not used for deliver_sm. Set to 0.
    pub sm_default_msg_id: u8,

    /// 4.3.17 sm_length: Length in octets of the short_message user data parameter.
    ///        Range: 0 to 254 octets. If sm_length is 0, then the short_message 
    ///        field is not present.
    pub sm_length: u8,

    /// 4.3.18 short_message: Up to 254 octets of short message user data.
    ///        For delivery receipts, this field contains the delivery receipt data.
    pub short_message: String,

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
    #[error("service_type exceeds maximum length of {MAX_SERVICE_TYPE_LENGTH} characters ({} with null terminator): {actual}", MAX_SERVICE_TYPE_LENGTH + 1)]
    ServiceTypeTooLong { actual: usize },

    #[error("source_addr exceeds maximum length of {MAX_SOURCE_ADDR_LENGTH} characters ({} with null terminator): {actual}", MAX_SOURCE_ADDR_LENGTH + 1)]
    SourceAddrTooLong { actual: usize },

    #[error("destination_addr exceeds maximum length of {MAX_DESTINATION_ADDR_LENGTH} characters ({} with null terminator): {actual}", MAX_DESTINATION_ADDR_LENGTH + 1)]
    DestinationAddrTooLong { actual: usize },

    #[error("sm_length ({sm_length}) does not match short_message length ({message_length})")]
    SmLengthMismatch {
        sm_length: u8,
        message_length: usize,
    },

    #[error("short_message exceeds maximum length of {MAX_SHORT_MESSAGE_LENGTH} bytes (use message_payload TLV for longer messages): {actual}")]
    ShortMessageTooLong { actual: usize },

    #[error("Cannot use both short_message and message_payload - they are mutually exclusive")]
    MutualExclusivityViolation,
}

impl DeliverSm {
    /// Validates the DeliverSm PDU according to SMPP v3.4 specification
    pub fn validate(&self) -> Result<(), DeliverSmValidationError> {
        // Validate field length constraints
        if self.service_type.len() > MAX_SERVICE_TYPE_LENGTH {
            return Err(DeliverSmValidationError::ServiceTypeTooLong {
                actual: self.service_type.len(),
            });
        }

        if self.source_addr.len() > MAX_SOURCE_ADDR_LENGTH {
            return Err(DeliverSmValidationError::SourceAddrTooLong {
                actual: self.source_addr.len(),
            });
        }

        if self.destination_addr.len() > MAX_DESTINATION_ADDR_LENGTH {
            return Err(DeliverSmValidationError::DestinationAddrTooLong {
                actual: self.destination_addr.len(),
            });
        }

        // Validate sm_length matches actual short_message length
        if self.sm_length as usize != self.short_message.len() {
            return Err(DeliverSmValidationError::SmLengthMismatch {
                sm_length: self.sm_length,
                message_length: self.short_message.len(),
            });
        }

        // Validate short message length constraints
        if self.short_message.len() > MAX_SHORT_MESSAGE_LENGTH {
            return Err(DeliverSmValidationError::ShortMessageTooLong {
                actual: self.short_message.len(),
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
    service_type: String,
    source_addr_ton: TypeOfNumber,
    source_addr_npi: NumericPlanIndicator,
    source_addr: String,
    dest_addr_ton: TypeOfNumber,
    dest_addr_npi: NumericPlanIndicator,
    destination_addr: String,
    esm_class: u8,
    protocol_id: u8,
    priority_flag: u8,
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
            service_type: String::new(),
            source_addr_ton: TypeOfNumber::Unknown,
            source_addr_npi: NumericPlanIndicator::Unknown,
            source_addr: String::new(),
            dest_addr_ton: TypeOfNumber::Unknown,
            dest_addr_npi: NumericPlanIndicator::Unknown,
            destination_addr: String::new(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: 0,
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

    pub fn esm_class(mut self, esm_class: u8) -> Self {
        self.esm_class = esm_class;
        self
    }

    pub fn data_coding(mut self, data_coding: u8) -> Self {
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
        self.sm_length = self.short_message.len() as u8;

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
    pub message_id: String,
}

impl ToBytes for DeliverSm {
    fn to_bytes(&self) -> Bytes {
        // Validate field constraints per SMPP v3.4 specification
        self.validate().expect("DeliverSm validation failed");

        let mut buffer = BytesMut::with_capacity(1024);

        // Write junk data that we'll replace later with the actual length
        buffer.put_u32(0_u32);

        buffer.put_u32(CommandId::DeliverSm as u32);
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
        buffer.put_u8(self.priority_flag);

        buffer.put(self.schedule_delivery_time.as_bytes());
        buffer.put_u8(b'\0');

        buffer.put(self.validity_period.as_bytes());
        buffer.put_u8(b'\0');

        buffer.put_u8(self.registered_delivery);
        buffer.put_u8(self.replace_if_present_flag);
        buffer.put_u8(self.data_coding);
        buffer.put_u8(self.sm_default_msg_id);

        buffer.put_u8(self.sm_length);
        buffer.put(self.short_message.as_bytes());

        // Optional parameters
        if let Some(user_message_reference) = &self.user_message_reference {
            buffer.extend_from_slice(&user_message_reference.to_bytes());
        }

        if let Some(source_port) = &self.source_port {
            buffer.extend_from_slice(&source_port.to_bytes());
        }

        if let Some(destination_port) = &self.destination_port {
            buffer.extend_from_slice(&destination_port.to_bytes());
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

        if let Some(user_data_header) = &self.user_data_header {
            buffer.extend_from_slice(&user_data_header.to_bytes());
        }

        if let Some(privacy_indicator) = &self.privacy_indicator {
            buffer.extend_from_slice(&privacy_indicator.to_bytes());
        }

        if let Some(callback_num) = &self.callback_num {
            buffer.extend_from_slice(&callback_num.to_bytes());
        }

        if let Some(source_subaddress) = &self.source_subaddress {
            buffer.extend_from_slice(&source_subaddress.to_bytes());
        }

        if let Some(dest_subaddress) = &self.dest_subaddress {
            buffer.extend_from_slice(&dest_subaddress.to_bytes());
        }

        if let Some(language_indicator) = &self.language_indicator {
            buffer.extend_from_slice(&language_indicator.to_bytes());
        }

        if let Some(its_session_info) = &self.its_session_info {
            buffer.extend_from_slice(&its_session_info.to_bytes());
        }

        if let Some(network_error_code) = &self.network_error_code {
            buffer.extend_from_slice(&network_error_code.to_bytes());
        }

        if let Some(message_payload) = &self.message_payload {
            buffer.extend_from_slice(&message_payload.to_bytes());
        }

        if let Some(delivery_failure_reason) = &self.delivery_failure_reason {
            buffer.extend_from_slice(&delivery_failure_reason.to_bytes());
        }

        if let Some(additional_status_info_text) = &self.additional_status_info_text {
            buffer.extend_from_slice(&additional_status_info_text.to_bytes());
        }

        if let Some(dpf_result) = &self.dpf_result {
            buffer.extend_from_slice(&dpf_result.to_bytes());
        }

        if let Some(set_dpf) = &self.set_dpf {
            buffer.extend_from_slice(&set_dpf.to_bytes());
        }

        if let Some(ms_availability_status) = &self.ms_availability_status {
            buffer.extend_from_slice(&ms_availability_status.to_bytes());
        }

        if let Some(receipted_message_id) = &self.receipted_message_id {
            buffer.extend_from_slice(&receipted_message_id.to_bytes());
        }

        if let Some(message_state) = &self.message_state {
            buffer.extend_from_slice(&message_state.to_bytes());
        }

        let length = buffer.len() as u32;

        let length_section = &mut buffer[0..][..4];
        length_section.copy_from_slice(&length.to_be_bytes());

        buffer.freeze()
    }
}

impl ToBytes for DeliverSmResponse {
    fn to_bytes(&self) -> Bytes {
        let length = 17 + self.message_id.len();

        let mut buffer = BytesMut::with_capacity(length);

        buffer.put_u32(length as u32);
        buffer.put_u32(CommandId::DeliverSmResp as u32);
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

    #[test]
    fn deliver_sm_to_bytes_basic() {
        let deliver_sm = DeliverSm {
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
            priority_flag: 0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 11,
            short_message: "Hello World".to_string(),
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
        assert!(bytes
            .windows(message_bytes.len())
            .any(|window| window == message_bytes));
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
        assert_eq!(deliver_sm.short_message, "Test message");
        assert_eq!(deliver_sm.sm_length, 12); // Length of "Test message"
    }

    #[test]
    fn deliver_sm_delivery_receipt() {
        let receipt_message = "id:1234567890 sub:001 dlvrd:001 submit date:2201011200 done date:2201011205 stat:DELIVRD err:000 text:Hello";
        
        let deliver_sm = DeliverSm::builder()
            .source_addr("1234567890")
            .destination_addr("0987654321")
            .esm_class(0x04) // Delivery receipt
            .short_message(receipt_message)
            .build()
            .unwrap();

        assert_eq!(deliver_sm.esm_class, 0x04);
        assert_eq!(deliver_sm.short_message, receipt_message);
        assert_eq!(deliver_sm.sm_length, receipt_message.len() as u8);
    }

    #[test]
    fn deliver_sm_response_to_bytes() {
        let deliver_sm_response = DeliverSmResponse {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            message_id: "".to_string(), // Usually NULL for deliver_sm_resp
        };

        let bytes = deliver_sm_response.to_bytes();

        // Verify header
        assert_eq!(&bytes[0..4], &(bytes.len() as u32).to_be_bytes()); // command_length
        assert_eq!(
            &bytes[4..8],
            &(CommandId::DeliverSmResp as u32).to_be_bytes()
        ); // command_id
        assert_eq!(&bytes[8..12], &(CommandStatus::Ok as u32).to_be_bytes()); // command_status
        assert_eq!(&bytes[12..16], &1u32.to_be_bytes()); // sequence_number

        // Should be minimum size: 16 bytes header + 1 byte null terminator
        assert_eq!(bytes.len(), 17);
        assert_eq!(bytes[16], 0); // null terminator
    }

    #[test]
    #[should_panic(expected = "SmLengthMismatch")]
    fn deliver_sm_validation_sm_length_mismatch() {
        let deliver_sm = DeliverSm {
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
            priority_flag: 0,
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