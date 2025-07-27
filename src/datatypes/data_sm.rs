// ABOUTME: Implements SMPP v3.4 data_sm and data_sm_resp PDUs for enhanced messaging with TLV support
// ABOUTME: Provides advanced messaging functionality per specification Section 4.7

use crate::datatypes::{
    AddressError, CommandId, CommandStatus, DataCoding, DestinationAddr, EsmClass, NumericPlanIndicator,
    ServiceType, SourceAddr, Tlv, TypeOfNumber,
};
use bytes::{Buf, BufMut, BytesMut};
use std::io::Cursor;
use thiserror::Error;

// Import codec traits
use crate::codec::{
    CodecError, Decodable, Encodable, PduHeader, decode_cstring, decode_u8, encode_cstring,
    encode_u8,
};

/// Validation errors for DataSm PDU
#[derive(Debug, Error)]
pub enum DataSmValidationError {
    #[error("Service type error: {0}")]
    ServiceType(#[from] crate::datatypes::ServiceTypeError),
    #[error("Source address error: {0}")]
    SourceAddr(#[from] AddressError),
    #[error("Data coding error: {0}")]
    DataCoding(#[from] crate::datatypes::DataCodingError),
    #[error("ESM class error: {0}")]
    EsmClass(#[from] crate::datatypes::EsmClassError),
}

/// SMPP v3.4 data_sm PDU (Section 4.7.1)
///
/// The data_sm operation is similar to the submit_sm operation in that it provides a means
/// of submitting a message to the SMSC for delivery to a specified destination. However,
/// data_sm is intended for more sophisticated messaging applications that require features
/// not available in submit_sm.
///
/// ## Key Features
/// - Enhanced messaging with TLV (Tag-Length-Value) parameters
/// - Support for large messages via message_payload TLV
/// - Concatenated message support
/// - Enhanced addressing options
/// - Delivery receipt management
///
/// ## Mandatory Parameters
/// - service_type: The service_type parameter
/// - source_addr_ton: Type of Number of message originator
/// - source_addr_npi: Numbering Plan Indicator of message originator  
/// - source_addr: Address of message originator
/// - dest_addr_ton: Type of Number for destination
/// - dest_addr_npi: Numbering Plan Indicator for destination
/// - destination_addr: Destination address
/// - esm_class: Enhanced Short Message Class
/// - registered_delivery: Registered delivery flag
/// - data_coding: Data coding scheme
///
/// ## Optional Parameters (TLVs)
/// - message_payload: The actual message data when short_message is not used
/// - source_port: Source port for WAP applications
/// - destination_port: Destination port for WAP applications
/// - sar_msg_ref_num: Reference number for concatenated messages
/// - sar_total_segments: Total number of segments in concatenated message
/// - sar_segment_seqnum: Sequence number of this segment
/// - user_message_reference: User-defined message reference
/// - privacy_indicator: Privacy level indicator
/// - callback_num: Callback number for voice mail notification
/// - source_subaddress: Source sub-address
/// - dest_subaddress: Destination sub-address
/// - user_data_header: User Data Header for advanced features
/// - payload_type: Type of payload data
/// - language_indicator: Language of the message
/// - its_reply_type: Interactive Teleservice reply type
/// - its_session_info: Interactive Teleservice session information
///
/// ## References
/// - SMPP v3.4 Specification Section 4.7.1
#[derive(Clone, Debug, PartialEq)]
pub struct DataSm {
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Mandatory parameters
    /// The service_type parameter can be used to indicate the SMS Application service
    /// associated with the message. Set to NULL for default SMSC settings.
    pub service_type: ServiceType,

    /// Type of Number of message originator.
    pub source_addr_ton: TypeOfNumber,

    /// Numbering Plan Indicator of message originator.
    pub source_addr_npi: NumericPlanIndicator,

    /// Address of message originator.
    /// Can be a phone number, short code, or alphanumeric identifier.
    pub source_addr: SourceAddr,

    /// Type of Number for destination.
    pub dest_addr_ton: TypeOfNumber,

    /// Numbering Plan Indicator for destination.
    pub dest_addr_npi: NumericPlanIndicator,

    /// Destination address.
    /// Can be a phone number, short code, or alphanumeric identifier.
    pub destination_addr: DestinationAddr,

    /// Enhanced Short Message Class.
    /// Indicates message mode and type, store-and-forward features.
    pub esm_class: EsmClass,

    /// Registered delivery flag.
    /// Indicates if and when delivery receipts are requested.
    pub registered_delivery: u8,

    /// Data coding scheme.
    /// Indicates the character encoding and message class.
    pub data_coding: DataCoding,

    // Optional TLV parameters
    /// Optional TLV parameters for enhanced messaging features.
    /// Common TLVs include message_payload, source_port, destination_port,
    /// SAR parameters for concatenated messages, and callback information.
    pub optional_parameters: Vec<Tlv>,
}

impl DataSm {
    /// Create a new DataSm PDU
    pub fn new(
        sequence_number: u32,
        service_type: ServiceType,
        source_addr_ton: TypeOfNumber,
        source_addr_npi: NumericPlanIndicator,
        source_addr: SourceAddr,
        dest_addr_ton: TypeOfNumber,
        dest_addr_npi: NumericPlanIndicator,
        destination_addr: DestinationAddr,
        esm_class: EsmClass,
        registered_delivery: u8,
        data_coding: DataCoding,
    ) -> Result<Self, DataSmValidationError> {
        let pdu = DataSm {
            command_status: CommandStatus::Ok, // Always 0 for requests
            sequence_number,
            service_type,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            dest_addr_ton,
            dest_addr_npi,
            destination_addr,
            esm_class,
            registered_delivery,
            data_coding,
            optional_parameters: Vec::new(),
        };

        // Validate the PDU
        pdu.validate()?;
        Ok(pdu)
    }

    /// Create a DataSm with message payload TLV
    pub fn with_message_payload(
        sequence_number: u32,
        service_type: ServiceType,
        source_addr_ton: TypeOfNumber,
        source_addr_npi: NumericPlanIndicator,
        source_addr: SourceAddr,
        dest_addr_ton: TypeOfNumber,
        dest_addr_npi: NumericPlanIndicator,
        destination_addr: DestinationAddr,
        esm_class: EsmClass,
        registered_delivery: u8,
        data_coding: DataCoding,
        message_payload: &[u8],
    ) -> Result<Self, DataSmValidationError> {
        let mut pdu = Self::new(
            sequence_number,
            service_type,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            dest_addr_ton,
            dest_addr_npi,
            destination_addr,
            esm_class,
            registered_delivery,
            data_coding,
        )?;

        // Add message payload TLV
        pdu.add_message_payload(message_payload);
        Ok(pdu)
    }

    /// Add a message payload TLV parameter
    pub fn add_message_payload(&mut self, payload: &[u8]) {
        let tlv = Tlv {
            tag: crate::datatypes::tlv::tags::MESSAGE_PAYLOAD,
            length: payload.len() as u16,
            value: bytes::Bytes::copy_from_slice(payload),
        };
        self.optional_parameters.push(tlv);
    }

    /// Add a source port TLV parameter
    pub fn add_source_port(&mut self, port: u16) {
        let tlv = Tlv {
            tag: crate::datatypes::tlv::tags::SOURCE_PORT,
            length: 2,
            value: bytes::Bytes::copy_from_slice(&port.to_be_bytes()),
        };
        self.optional_parameters.push(tlv);
    }

    /// Add a destination port TLV parameter
    pub fn add_destination_port(&mut self, port: u16) {
        let tlv = Tlv {
            tag: crate::datatypes::tlv::tags::DESTINATION_PORT,
            length: 2,
            value: bytes::Bytes::copy_from_slice(&port.to_be_bytes()),
        };
        self.optional_parameters.push(tlv);
    }

    /// Add SAR (Segmentation and Reassembly) parameters for concatenated messages
    pub fn add_sar_parameters(&mut self, msg_ref: u16, total_segments: u8, segment_seq: u8) {
        // Message reference number
        let ref_tlv = Tlv {
            tag: crate::datatypes::tlv::tags::SAR_MSG_REF_NUM,
            length: 2,
            value: bytes::Bytes::copy_from_slice(&msg_ref.to_be_bytes()),
        };
        self.optional_parameters.push(ref_tlv);

        // Total segments
        let total_tlv = Tlv {
            tag: crate::datatypes::tlv::tags::SAR_TOTAL_SEGMENTS,
            length: 1,
            value: bytes::Bytes::copy_from_slice(&[total_segments]),
        };
        self.optional_parameters.push(total_tlv);

        // Segment sequence number
        let seq_tlv = Tlv {
            tag: crate::datatypes::tlv::tags::SAR_SEGMENT_SEQNUM,
            length: 1,
            value: bytes::Bytes::copy_from_slice(&[segment_seq]),
        };
        self.optional_parameters.push(seq_tlv);
    }

    /// Add a custom TLV parameter
    pub fn add_tlv(&mut self, tlv: Tlv) {
        self.optional_parameters.push(tlv);
    }

    /// Get the message payload from TLV parameters if present
    pub fn message_payload(&self) -> Option<&bytes::Bytes> {
        self.optional_parameters
            .iter()
            .find(|tlv| tlv.tag == crate::datatypes::tlv::tags::MESSAGE_PAYLOAD)
            .map(|tlv| &tlv.value)
    }

    /// Get the source port from TLV parameters if present
    pub fn source_port(&self) -> Option<u16> {
        self.optional_parameters
            .iter()
            .find(|tlv| tlv.tag == crate::datatypes::tlv::tags::SOURCE_PORT)
            .and_then(|tlv| {
                if tlv.value.len() == 2 {
                    Some(u16::from_be_bytes([tlv.value[0], tlv.value[1]]))
                } else {
                    None
                }
            })
    }

    /// Get the destination port from TLV parameters if present
    pub fn destination_port(&self) -> Option<u16> {
        self.optional_parameters
            .iter()
            .find(|tlv| tlv.tag == crate::datatypes::tlv::tags::DESTINATION_PORT)
            .and_then(|tlv| {
                if tlv.value.len() == 2 {
                    Some(u16::from_be_bytes([tlv.value[0], tlv.value[1]]))
                } else {
                    None
                }
            })
    }

    /// Check if this is a concatenated message
    pub fn is_concatenated(&self) -> bool {
        self.optional_parameters.iter().any(|tlv| {
            tlv.tag == crate::datatypes::tlv::tags::SAR_MSG_REF_NUM
        })
    }

    /// Validate the DataSm PDU
    fn validate(&self) -> Result<(), DataSmValidationError> {
        // service_type validation is handled by ServiceType type
        // source_addr validation is handled by SourceAddr type
        // destination_addr validation is handled by DestinationAddr type
        // data_coding validation is handled by DataCoding type
        // esm_class validation is handled by EsmClass type
        Ok(())
    }
}

impl Encodable for DataSm {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // PDU Header (will be filled by codec)
        buf.put_u32(0); // command_length (placeholder)
        buf.put_u32(CommandId::DataSm as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Mandatory parameters
        // service_type (6 octets, null-terminated with padding)
        encode_cstring(buf, self.service_type.as_str(), 6);

        // source_addr_ton (1 octet)
        encode_u8(buf, self.source_addr_ton as u8);

        // source_addr_npi (1 octet)
        encode_u8(buf, self.source_addr_npi as u8);

        // source_addr (21 octets, null-terminated with padding)
        encode_cstring(buf, self.source_addr.as_str().unwrap_or(""), 21);

        // dest_addr_ton (1 octet)
        encode_u8(buf, self.dest_addr_ton as u8);

        // dest_addr_npi (1 octet)
        encode_u8(buf, self.dest_addr_npi as u8);

        // destination_addr (21 octets, null-terminated with padding)
        encode_cstring(buf, self.destination_addr.as_str().unwrap_or(""), 21);

        // esm_class (1 octet)
        encode_u8(buf, self.esm_class.to_byte());

        // registered_delivery (1 octet)
        encode_u8(buf, self.registered_delivery);

        // data_coding (1 octet)
        encode_u8(buf, self.data_coding.to_byte());

        // Optional TLV parameters
        for tlv in &self.optional_parameters {
            tlv.encode(buf)?;
        }

        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = 16 + 6 + 1 + 1 + 21 + 1 + 1 + 21 + 1 + 1 + 1; // header + mandatory fields

        // Add TLV sizes
        for tlv in &self.optional_parameters {
            size += tlv.encoded_size();
        }

        size
    }
}

impl Decodable for DataSm {
    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory parameters
        let service_type_str = decode_cstring(buf, 6, "service_type")?;
        let service_type = ServiceType::new(&service_type_str).map_err(|e| {
            CodecError::FieldValidation {
                field: "service_type",
                reason: format!("{e}"),
            }
        })?;

        let source_addr_ton =
            TypeOfNumber::try_from(decode_u8(buf)?).map_err(|_| CodecError::FieldValidation {
                field: "source_addr_ton",
                reason: "Invalid TypeOfNumber value".to_string(),
            })?;

        let source_addr_npi = NumericPlanIndicator::try_from(decode_u8(buf)?).map_err(|_| {
            CodecError::FieldValidation {
                field: "source_addr_npi",
                reason: "Invalid NumericPlanIndicator value".to_string(),
            }
        })?;

        let source_addr_str = decode_cstring(buf, 21, "source_addr")?;
        let source_addr = SourceAddr::new(&source_addr_str, source_addr_ton).map_err(|e| {
            CodecError::FieldValidation {
                field: "source_addr",
                reason: format!("{e}"),
            }
        })?;

        let dest_addr_ton =
            TypeOfNumber::try_from(decode_u8(buf)?).map_err(|_| CodecError::FieldValidation {
                field: "dest_addr_ton",
                reason: "Invalid TypeOfNumber value".to_string(),
            })?;

        let dest_addr_npi = NumericPlanIndicator::try_from(decode_u8(buf)?).map_err(|_| {
            CodecError::FieldValidation {
                field: "dest_addr_npi",
                reason: "Invalid NumericPlanIndicator value".to_string(),
            }
        })?;

        let destination_addr_str = decode_cstring(buf, 21, "destination_addr")?;
        let destination_addr = DestinationAddr::new(&destination_addr_str, dest_addr_ton).map_err(|e| {
            CodecError::FieldValidation {
                field: "destination_addr",
                reason: format!("{e}"),
            }
        })?;

        let esm_class_byte = decode_u8(buf)?;
        let esm_class = EsmClass::from_byte(esm_class_byte).map_err(|e| {
            CodecError::FieldValidation {
                field: "esm_class",
                reason: format!("{e}"),
            }
        })?;

        let registered_delivery = decode_u8(buf)?;

        let data_coding_byte = decode_u8(buf)?;
        let data_coding = DataCoding::from_byte(data_coding_byte);

        // Decode optional TLV parameters
        let mut optional_parameters = Vec::new();
        while buf.remaining() > 0 {
            match Tlv::decode(buf) {
                Ok(tlv) => optional_parameters.push(tlv),
                Err(CodecError::Incomplete) => break, // End of TLVs
                Err(e) => return Err(e),
            }
        }

        Ok(DataSm {
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
            registered_delivery,
            data_coding,
            optional_parameters,
        })
    }

    fn command_id() -> CommandId {
        CommandId::DataSm
    }
}

/// Validation errors for DataSmResponse PDU
#[derive(Debug, Error)]
pub enum DataSmResponseValidationError {
    #[error("Message ID error: {0}")]
    MessageId(#[from] crate::datatypes::FixedStringError),
}

/// SMPP v3.4 data_sm_resp PDU (Section 4.7.2)
///
/// The data_sm_resp PDU is used to return the result of a data_sm request.
/// If the message was accepted for delivery, the response includes a message ID
/// that can be used for subsequent query, replace, or cancel operations.
///
/// ## Mandatory Parameters
/// - message_id: Message ID assigned by SMSC (if successful)
///
/// ## Optional Parameters (TLVs)
/// - delivery_failure_reason: Reason for delivery failure
/// - network_error_code: Network-specific error information
/// - additional_status_info_text: Additional status information
///
/// ## References
/// - SMPP v3.4 Specification Section 4.7.2
#[derive(Clone, Debug, PartialEq)]
pub struct DataSmResponse {
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Mandatory parameters
    /// Message ID assigned by the SMSC.
    /// Set to empty string on error conditions.
    pub message_id: crate::datatypes::MessageId,

    // Optional TLV parameters
    /// Optional TLV parameters for additional response information.
    /// Common TLVs include delivery_failure_reason, network_error_code,
    /// and additional_status_info_text for error conditions.
    pub optional_parameters: Vec<Tlv>,
}

impl DataSmResponse {
    /// Create a new DataSmResponse PDU
    pub fn new(
        sequence_number: u32,
        command_status: CommandStatus,
        message_id: crate::datatypes::MessageId,
    ) -> Result<Self, DataSmResponseValidationError> {
        let pdu = DataSmResponse {
            command_status,
            sequence_number,
            message_id,
            optional_parameters: Vec::new(),
        };

        // Validate the PDU
        pdu.validate()?;
        Ok(pdu)
    }

    /// Create a successful DataSmResponse
    pub fn success(sequence_number: u32, message_id: crate::datatypes::MessageId) -> Self {
        DataSmResponse {
            command_status: CommandStatus::Ok,
            sequence_number,
            message_id,
            optional_parameters: Vec::new(),
        }
    }

    /// Create an error DataSmResponse
    pub fn error(sequence_number: u32, command_status: CommandStatus) -> Self {
        DataSmResponse {
            command_status,
            sequence_number,
            message_id: crate::datatypes::MessageId::new(b"").unwrap_or_else(|_| crate::datatypes::MessageId::new(b"ERROR").unwrap()), // Empty on error
            optional_parameters: Vec::new(),
        }
    }

    /// Add a custom TLV parameter
    pub fn add_tlv(&mut self, tlv: Tlv) {
        self.optional_parameters.push(tlv);
    }

    /// Add delivery failure reason TLV
    pub fn add_delivery_failure_reason(&mut self, reason: u8) {
        let tlv = Tlv {
            tag: crate::datatypes::tlv::tags::DELIVERY_FAILURE_REASON,
            length: 1,
            value: bytes::Bytes::copy_from_slice(&[reason]),
        };
        self.optional_parameters.push(tlv);
    }

    /// Add network error code TLV
    pub fn add_network_error_code(&mut self, network_type: u8, error_code: u16) {
        let mut value = Vec::new();
        value.push(network_type);
        value.extend_from_slice(&error_code.to_be_bytes());
        
        let tlv = Tlv {
            tag: crate::datatypes::tlv::tags::NETWORK_ERROR_CODE,
            length: 3,
            value: bytes::Bytes::from(value),
        };
        self.optional_parameters.push(tlv);
    }

    /// Validate the DataSmResponse PDU
    fn validate(&self) -> Result<(), DataSmResponseValidationError> {
        // message_id validation is handled by MessageId type
        Ok(())
    }
}

impl Encodable for DataSmResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // PDU Header (will be filled by codec)
        buf.put_u32(0); // command_length (placeholder)
        buf.put_u32(CommandId::DataSmResp as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Mandatory parameters
        // message_id (65 octets, null-terminated with padding)
        encode_cstring(buf, self.message_id.as_str().unwrap_or(""), 65);

        // Optional TLV parameters
        for tlv in &self.optional_parameters {
            tlv.encode(buf)?;
        }

        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = 16 + 65; // header + message_id

        // Add TLV sizes
        for tlv in &self.optional_parameters {
            size += tlv.encoded_size();
        }

        size
    }
}

impl Decodable for DataSmResponse {
    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory parameters
        let message_id_str = decode_cstring(buf, 65, "message_id")?;
        let message_id =
            crate::datatypes::MessageId::new(message_id_str.as_bytes()).map_err(|e| CodecError::FieldValidation {
                field: "message_id",
                reason: format!("{e}"),
            })?;

        // Decode optional TLV parameters
        let mut optional_parameters = Vec::new();
        while buf.remaining() > 0 {
            match Tlv::decode(buf) {
                Ok(tlv) => optional_parameters.push(tlv),
                Err(CodecError::Incomplete) => break, // End of TLVs
                Err(e) => return Err(e),
            }
        }

        Ok(DataSmResponse {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            message_id,
            optional_parameters,
        })
    }

    fn command_id() -> CommandId {
        CommandId::DataSmResp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datatypes::{NumericPlanIndicator, TypeOfNumber};

    #[test]
    fn test_data_sm_creation() {
        let service_type = ServiceType::new("").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let destination_addr = DestinationAddr::new("0987654321", TypeOfNumber::International).unwrap();
        let esm_class = EsmClass::default();
        let data_coding = DataCoding::default();

        let data_sm = DataSm::new(
            123,
            service_type,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            destination_addr,
            esm_class,
            0x01, // registered_delivery
            data_coding,
        )
        .unwrap();

        assert_eq!(data_sm.sequence_number, 123);
        assert_eq!(data_sm.command_status, CommandStatus::Ok);
        assert_eq!(data_sm.service_type.as_str(), "");
        assert_eq!(data_sm.source_addr_ton, TypeOfNumber::International);
        assert_eq!(data_sm.source_addr_npi, NumericPlanIndicator::Isdn);
        assert_eq!(data_sm.source_addr.as_str().unwrap(), "1234567890");
        assert_eq!(data_sm.dest_addr_ton, TypeOfNumber::International);
        assert_eq!(data_sm.dest_addr_npi, NumericPlanIndicator::Isdn);
        assert_eq!(data_sm.destination_addr.as_str().unwrap(), "0987654321");
        assert_eq!(data_sm.registered_delivery, 0x01);
        assert!(data_sm.optional_parameters.is_empty());
    }

    #[test]
    fn test_data_sm_with_message_payload() {
        let service_type = ServiceType::new("WAP").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let destination_addr = DestinationAddr::new("0987654321", TypeOfNumber::International).unwrap();
        let esm_class = EsmClass::default();
        let data_coding = DataCoding::default();
        let message_payload = b"Hello from data_sm!";

        let data_sm = DataSm::with_message_payload(
            456,
            service_type,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            destination_addr,
            esm_class,
            0x00,
            data_coding,
            message_payload,
        )
        .unwrap();

        assert_eq!(data_sm.sequence_number, 456);
        assert_eq!(data_sm.service_type.as_str(), "WAP");
        assert_eq!(data_sm.optional_parameters.len(), 1);
        
        let payload = data_sm.message_payload().unwrap();
        assert_eq!(payload.as_ref(), message_payload);
    }

    #[test]
    fn test_data_sm_encoding_decoding() {
        let service_type = ServiceType::new("SMS").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let destination_addr = DestinationAddr::new("0987654321", TypeOfNumber::International).unwrap();
        let esm_class = EsmClass::default();
        let data_coding = DataCoding::default();

        let original = DataSm::new(
            789,
            service_type,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            destination_addr,
            esm_class,
            0x01,
            data_coding,
        )
        .unwrap();

        // Test encoding
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Test decoding
        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::DataSm,
            command_status: CommandStatus::Ok,
            sequence_number: 789,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = DataSm::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_data_sm_with_ports() {
        let service_type = ServiceType::new("WAP").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let destination_addr = DestinationAddr::new("0987654321", TypeOfNumber::International).unwrap();
        let esm_class = EsmClass::default();
        let data_coding = DataCoding::default();

        let mut data_sm = DataSm::new(
            100,
            service_type,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            destination_addr,
            esm_class,
            0x00,
            data_coding,
        )
        .unwrap();

        // Add source and destination ports
        data_sm.add_source_port(8080);
        data_sm.add_destination_port(9999);

        assert_eq!(data_sm.source_port(), Some(8080));
        assert_eq!(data_sm.destination_port(), Some(9999));
        assert_eq!(data_sm.optional_parameters.len(), 2);
    }

    #[test]
    fn test_data_sm_with_sar_parameters() {
        let service_type = ServiceType::new("").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let destination_addr = DestinationAddr::new("0987654321", TypeOfNumber::International).unwrap();
        let esm_class = EsmClass::default();
        let data_coding = DataCoding::default();

        let mut data_sm = DataSm::new(
            200,
            service_type,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            destination_addr,
            esm_class,
            0x00,
            data_coding,
        )
        .unwrap();

        // Add SAR parameters for concatenated message
        data_sm.add_sar_parameters(12345, 3, 1);

        assert!(data_sm.is_concatenated());
        assert_eq!(data_sm.optional_parameters.len(), 3);
    }

    #[test]
    fn test_data_sm_response_creation() {
        let message_id = crate::datatypes::MessageId::new(b"MSG12345").unwrap();
        let response = DataSmResponse::new(789, CommandStatus::Ok, message_id).unwrap();

        assert_eq!(response.sequence_number, 789);
        assert_eq!(response.command_status, CommandStatus::Ok);
        assert_eq!(response.message_id.as_str().unwrap(), "MSG12345");
        assert!(response.optional_parameters.is_empty());
    }

    #[test]
    fn test_data_sm_response_success() {
        let message_id = crate::datatypes::MessageId::new(b"SUCCESS1").unwrap();
        let response = DataSmResponse::success(456, message_id);

        assert_eq!(response.sequence_number, 456);
        assert_eq!(response.command_status, CommandStatus::Ok);
        assert_eq!(response.message_id.as_str().unwrap(), "SUCCESS1");
    }

    #[test]
    fn test_data_sm_response_error() {
        let response = DataSmResponse::error(789, CommandStatus::InvalidDestinationAddress);

        assert_eq!(response.sequence_number, 789);
        assert_eq!(response.command_status, CommandStatus::InvalidDestinationAddress);
        assert_eq!(response.message_id.as_str().unwrap_or(""), ""); // Empty on error
    }

    #[test]
    fn test_data_sm_response_encoding_decoding() {
        let message_id = crate::datatypes::MessageId::new(b"TEST001").unwrap();
        let original = DataSmResponse::success(999, message_id);

        // Test encoding
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Test decoding
        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::DataSmResp,
            command_status: CommandStatus::Ok,
            sequence_number: 999,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = DataSmResponse::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_data_sm_response_with_failure_reason() {
        let mut response = DataSmResponse::error(555, CommandStatus::MessageQueueFull);
        response.add_delivery_failure_reason(0x02); // Temporary failure

        assert_eq!(response.optional_parameters.len(), 1);
        assert_eq!(response.optional_parameters[0].tag, crate::datatypes::tlv::tags::DELIVERY_FAILURE_REASON);
        assert_eq!(response.optional_parameters[0].value.as_ref(), &[0x02]);
    }

    #[test]
    fn test_data_sm_response_with_network_error() {
        let mut response = DataSmResponse::error(666, CommandStatus::SystemError);
        response.add_network_error_code(0x01, 0x1234); // Network type 1, error code 0x1234

        assert_eq!(response.optional_parameters.len(), 1);
        assert_eq!(response.optional_parameters[0].tag, crate::datatypes::tlv::tags::NETWORK_ERROR_CODE);
        assert_eq!(response.optional_parameters[0].value.as_ref(), &[0x01, 0x12, 0x34]);
    }
}