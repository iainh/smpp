// ABOUTME: Implements SMPP v3.4 submit_multi and submit_multi_resp PDUs for multi-destination messaging
// ABOUTME: Provides bulk messaging functionality per specification Section 4.4

use crate::datatypes::{
    AddressError, CommandId, CommandStatus, DataCoding, EsmClass, FixedStringError, MessageId,
    NumericPlanIndicator, PriorityFlag, ServiceType, ShortMessage, SourceAddr, Tlv, TypeOfNumber,
    ValidityPeriod, ScheduleDeliveryTime,
};
use bytes::{Buf, BufMut, BytesMut};
use std::io::Cursor;
use thiserror::Error;

// Import codec traits
use crate::codec::{
    CodecError, Decodable, Encodable, PduHeader, decode_cstring, decode_u8, encode_cstring,
    encode_u8,
};

/// Validation errors for SubmitMulti PDU
#[derive(Debug, Error)]
pub enum SubmitMultiValidationError {
    #[error("Service type error: {0}")]
    ServiceType(#[from] crate::datatypes::ServiceTypeError),
    #[error("Source address error: {0}")]
    SourceAddr(#[from] AddressError),
    #[error("Data coding error: {0}")]
    DataCoding(#[from] crate::datatypes::DataCodingError),
    #[error("ESM class error: {0}")]
    EsmClass(#[from] crate::datatypes::EsmClassError),
    #[error("Short message error: {0}")]
    ShortMessage(#[from] FixedStringError),
    #[error("Too many destinations: {count}, maximum allowed: {max}")]
    TooManyDestinations { count: usize, max: usize },
    #[error("No destinations specified")]
    NoDestinations,
    #[error("Message length validation failed: sm_length {sm_length} does not match actual length {actual_length}")]
    MessageLengthMismatch { sm_length: u8, actual_length: usize },
}

/// SMPP v3.4 destination address types for submit_multi
#[derive(Clone, Debug, PartialEq)]
pub enum DestinationAddress {
    /// Standard destination address (SME address)
    SmeAddress {
        dest_flag: u8, // Must be 1 for SME address
        dest_addr_ton: TypeOfNumber,
        dest_addr_npi: NumericPlanIndicator,
        destination_addr: String, // Variable length, null-terminated
    },
    /// Distribution list address
    DistributionList {
        dest_flag: u8, // Must be 2 for distribution list
        dl_name: String, // Distribution list name, variable length, null-terminated
    },
}

impl DestinationAddress {
    /// Create a new SME destination address
    pub fn sme_address(
        dest_addr_ton: TypeOfNumber,
        dest_addr_npi: NumericPlanIndicator,
        destination_addr: &str,
    ) -> Result<Self, AddressError> {
        // Validate address format and length
        if destination_addr.len() > 20 {
            return Err(AddressError::TooLong {
                max_len: 20,
                actual_len: destination_addr.len(),
            });
        }

        Ok(DestinationAddress::SmeAddress {
            dest_flag: 1,
            dest_addr_ton,
            dest_addr_npi,
            destination_addr: destination_addr.to_string(),
        })
    }

    /// Create a new distribution list destination
    pub fn distribution_list(dl_name: &str) -> Result<Self, AddressError> {
        // Validate distribution list name length
        if dl_name.len() > 20 {
            return Err(AddressError::TooLong {
                max_len: 20,
                actual_len: dl_name.len(),
            });
        }

        Ok(DestinationAddress::DistributionList {
            dest_flag: 2,
            dl_name: dl_name.to_string(),
        })
    }

    /// Get the destination flag value
    pub fn dest_flag(&self) -> u8 {
        match self {
            DestinationAddress::SmeAddress { dest_flag, .. } => *dest_flag,
            DestinationAddress::DistributionList { dest_flag, .. } => *dest_flag,
        }
    }

    /// Encode this destination address to buffer
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        match self {
            DestinationAddress::SmeAddress {
                dest_flag,
                dest_addr_ton,
                dest_addr_npi,
                destination_addr,
            } => {
                encode_u8(buf, *dest_flag);
                encode_u8(buf, *dest_addr_ton as u8);
                encode_u8(buf, *dest_addr_npi as u8);
                // Variable-length null-terminated string
                buf.extend_from_slice(destination_addr.as_bytes());
                buf.put_u8(0); // null terminator
            }
            DestinationAddress::DistributionList { dest_flag, dl_name } => {
                encode_u8(buf, *dest_flag);
                // Variable-length null-terminated string
                buf.extend_from_slice(dl_name.as_bytes());
                buf.put_u8(0); // null terminator
            }
        }
        Ok(())
    }

    /// Decode a destination address from buffer
    pub fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let dest_flag = decode_u8(buf)?;

        match dest_flag {
            1 => {
                // SME address
                let dest_addr_ton = TypeOfNumber::try_from(decode_u8(buf)?).map_err(|_| {
                    CodecError::FieldValidation {
                        field: "dest_addr_ton",
                        reason: "Invalid TypeOfNumber value".to_string(),
                    }
                })?;

                let dest_addr_npi = NumericPlanIndicator::try_from(decode_u8(buf)?).map_err(|_| {
                    CodecError::FieldValidation {
                        field: "dest_addr_npi",
                        reason: "Invalid NumericPlanIndicator value".to_string(),
                    }
                })?;

                // Read null-terminated destination address
                let destination_addr = decode_null_terminated_string(buf, "destination_addr")?;

                Ok(DestinationAddress::SmeAddress {
                    dest_flag,
                    dest_addr_ton,
                    dest_addr_npi,
                    destination_addr,
                })
            }
            2 => {
                // Distribution list
                let dl_name = decode_null_terminated_string(buf, "dl_name")?;

                Ok(DestinationAddress::DistributionList { dest_flag, dl_name })
            }
            _ => Err(CodecError::FieldValidation {
                field: "dest_flag",
                reason: format!("Invalid destination flag: {}, expected 1 or 2", dest_flag),
            }),
        }
    }

    /// Calculate the encoded size of this destination address
    pub fn encoded_size(&self) -> usize {
        match self {
            DestinationAddress::SmeAddress { destination_addr, .. } => {
                1 + 1 + 1 + destination_addr.len() + 1 // dest_flag + ton + npi + addr + null
            }
            DestinationAddress::DistributionList { dl_name, .. } => {
                1 + dl_name.len() + 1 // dest_flag + name + null
            }
        }
    }
}

/// Helper function to decode null-terminated strings of variable length
fn decode_null_terminated_string(buf: &mut Cursor<&[u8]>, field_name: &'static str) -> Result<String, CodecError> {
    let mut bytes = Vec::new();
    
    while buf.remaining() > 0 {
        let byte = decode_u8(buf)?;
        if byte == 0 {
            break; // Found null terminator
        }
        bytes.push(byte);
        
        // Prevent infinite loop - reasonable string length limit
        if bytes.len() > 255 {
            return Err(CodecError::FieldValidation {
                field: field_name,
                reason: "String too long (>255 bytes)".to_string(),
            });
        }
    }

    String::from_utf8(bytes).map_err(|e| CodecError::Utf8Error {
        field: field_name,
        source: e,
    })
}

/// SMPP v3.4 submit_multi PDU (Section 4.4.1)
///
/// The submit_multi operation is used to submit an SMS message to multiple destinations.
/// This PDU allows a single message to be sent to up to 255 destinations in a single
/// request, which is more efficient than sending individual submit_sm PDUs.
///
/// ## Key Features
/// - Support for up to 255 destinations per PDU
/// - Mixed destination types (SME addresses and distribution lists)
/// - Same message content delivered to all destinations
/// - Efficient bulk messaging operation
/// - Optional TLV parameters for enhanced features
///
/// ## Mandatory Parameters
/// - service_type: The service_type parameter
/// - source_addr_ton: Type of Number of message originator
/// - source_addr_npi: Numbering Plan Indicator of message originator
/// - source_addr: Address of message originator
/// - number_of_dests: Number of destination addresses (1-255)
/// - dest_addresses: List of destination addresses
/// - esm_class: Enhanced Short Message Class
/// - protocol_id: Protocol identifier
/// - priority_flag: Priority level of the message
/// - schedule_delivery_time: Scheduled delivery time
/// - validity_period: Message validity period
/// - registered_delivery: Registered delivery flag
/// - replace_if_present_flag: Replace message flag
/// - data_coding: Data coding scheme
/// - sm_default_msg_id: Default message identifier
/// - sm_length: Length of short message
/// - short_message: Short message content
///
/// ## References
/// - SMPP v3.4 Specification Section 4.4.1
#[derive(Clone, Debug, PartialEq)]
pub struct SubmitMulti {
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

    /// Number of destination addresses in the list.
    /// Must be between 1 and 255 inclusive.
    pub number_of_dests: u8,

    /// List of destination addresses.
    /// Can contain a mix of SME addresses and distribution lists.
    pub dest_addresses: Vec<DestinationAddress>,

    /// Enhanced Short Message Class.
    /// Indicates message mode and type, store-and-forward features.
    pub esm_class: EsmClass,

    /// Protocol identifier.
    /// Used to indicate the higher layer protocol above SMS.
    pub protocol_id: u8,

    /// Priority level of the message.
    /// Indicates the priority at which the message should be scheduled by the SMSC.
    pub priority_flag: PriorityFlag,

    /// Scheduled delivery time.
    /// Set to NULL for immediate delivery.
    pub schedule_delivery_time: ScheduleDeliveryTime,

    /// Message validity period.
    /// Set to NULL to request the SMSC default validity period.
    pub validity_period: ValidityPeriod,

    /// Registered delivery flag.
    /// Indicates if and when delivery receipts are requested.
    pub registered_delivery: u8,

    /// Replace message if present flag.
    /// Indicates if the message should replace any existing message with the same
    /// source address and destination address.
    pub replace_if_present_flag: u8,

    /// Data coding scheme.
    /// Indicates the character encoding and message class.
    pub data_coding: DataCoding,

    /// Default message identifier.
    /// Used when the short message is replaced by a predefined message.
    pub sm_default_msg_id: u8,

    /// Length of short message.
    /// Must match the actual length of the short_message field.
    pub sm_length: u8,

    /// Short message content.
    /// The actual message data to be delivered to all destinations.
    pub short_message: ShortMessage,

    // Optional TLV parameters
    /// Optional TLV parameters for enhanced messaging features.
    /// Can include message_payload for large messages, callback numbers, etc.
    pub optional_parameters: Vec<Tlv>,
}

impl SubmitMulti {
    /// Maximum number of destinations allowed per submit_multi PDU
    pub const MAX_DESTINATIONS: usize = 255;

    /// Create a new SubmitMulti PDU
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence_number: u32,
        service_type: ServiceType,
        source_addr_ton: TypeOfNumber,
        source_addr_npi: NumericPlanIndicator,
        source_addr: SourceAddr,
        dest_addresses: Vec<DestinationAddress>,
        esm_class: EsmClass,
        protocol_id: u8,
        priority_flag: PriorityFlag,
        schedule_delivery_time: ScheduleDeliveryTime,
        validity_period: ValidityPeriod,
        registered_delivery: u8,
        replace_if_present_flag: u8,
        data_coding: DataCoding,
        sm_default_msg_id: u8,
        short_message: ShortMessage,
    ) -> Result<Self, SubmitMultiValidationError> {
        // Validate destination count
        if dest_addresses.is_empty() {
            return Err(SubmitMultiValidationError::NoDestinations);
        }
        if dest_addresses.len() > Self::MAX_DESTINATIONS {
            return Err(SubmitMultiValidationError::TooManyDestinations {
                count: dest_addresses.len(),
                max: Self::MAX_DESTINATIONS,
            });
        }

        let number_of_dests = dest_addresses.len() as u8;
        let sm_length = short_message.len();

        let pdu = SubmitMulti {
            command_status: CommandStatus::Ok, // Always 0 for requests
            sequence_number,
            service_type,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            number_of_dests,
            dest_addresses,
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
            optional_parameters: Vec::new(),
        };

        // Validate the PDU
        pdu.validate()?;
        Ok(pdu)
    }

    /// Add a SME destination address
    pub fn add_sme_destination(
        &mut self,
        dest_addr_ton: TypeOfNumber,
        dest_addr_npi: NumericPlanIndicator,
        destination_addr: &str,
    ) -> Result<(), SubmitMultiValidationError> {
        if self.dest_addresses.len() >= Self::MAX_DESTINATIONS {
            return Err(SubmitMultiValidationError::TooManyDestinations {
                count: self.dest_addresses.len() + 1,
                max: Self::MAX_DESTINATIONS,
            });
        }

        let dest_addr = DestinationAddress::sme_address(dest_addr_ton, dest_addr_npi, destination_addr)?;
        self.dest_addresses.push(dest_addr);
        self.number_of_dests = self.dest_addresses.len() as u8;
        Ok(())
    }

    /// Add a distribution list destination
    pub fn add_distribution_list(&mut self, dl_name: &str) -> Result<(), SubmitMultiValidationError> {
        if self.dest_addresses.len() >= Self::MAX_DESTINATIONS {
            return Err(SubmitMultiValidationError::TooManyDestinations {
                count: self.dest_addresses.len() + 1,
                max: Self::MAX_DESTINATIONS,
            });
        }

        let dest_addr = DestinationAddress::distribution_list(dl_name)?;
        self.dest_addresses.push(dest_addr);
        self.number_of_dests = self.dest_addresses.len() as u8;
        Ok(())
    }

    /// Add a custom TLV parameter
    pub fn add_tlv(&mut self, tlv: Tlv) {
        self.optional_parameters.push(tlv);
    }

    /// Get the total number of destinations
    pub fn destination_count(&self) -> usize {
        self.dest_addresses.len()
    }

    /// Check if this PDU has reached the maximum destination limit
    pub fn is_at_capacity(&self) -> bool {
        self.dest_addresses.len() >= Self::MAX_DESTINATIONS
    }

    /// Validate the SubmitMulti PDU
    fn validate(&self) -> Result<(), SubmitMultiValidationError> {
        // Validate destination count consistency
        if self.number_of_dests as usize != self.dest_addresses.len() {
            return Err(SubmitMultiValidationError::TooManyDestinations {
                count: self.dest_addresses.len(),
                max: self.number_of_dests as usize,
            });
        }

        // Validate message length consistency
        if self.sm_length != self.short_message.len() {
            return Err(SubmitMultiValidationError::MessageLengthMismatch {
                sm_length: self.sm_length,
                actual_length: self.short_message.len() as usize,
            });
        }

        // Other validations are handled by the respective data types
        Ok(())
    }
}

impl Encodable for SubmitMulti {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // PDU Header (will be filled by codec)
        buf.put_u32(0); // command_length (placeholder)
        buf.put_u32(CommandId::SubmitMulti as u32);
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

        // number_of_dests (1 octet)
        encode_u8(buf, self.number_of_dests);

        // dest_addresses (variable length)
        for dest_addr in &self.dest_addresses {
            dest_addr.encode(buf)?;
        }

        // esm_class (1 octet)
        encode_u8(buf, self.esm_class.to_byte());

        // protocol_id (1 octet)
        encode_u8(buf, self.protocol_id);

        // priority_flag (1 octet)
        encode_u8(buf, self.priority_flag as u8);

        // schedule_delivery_time (17 octets, null-terminated with padding)
        encode_cstring(buf, self.schedule_delivery_time.as_str().unwrap_or(""), 17);

        // validity_period (17 octets, null-terminated with padding)
        encode_cstring(buf, self.validity_period.as_str().unwrap_or(""), 17);

        // registered_delivery (1 octet)
        encode_u8(buf, self.registered_delivery);

        // replace_if_present_flag (1 octet)
        encode_u8(buf, self.replace_if_present_flag);

        // data_coding (1 octet)
        encode_u8(buf, self.data_coding.to_byte());

        // sm_default_msg_id (1 octet)
        encode_u8(buf, self.sm_default_msg_id);

        // sm_length (1 octet)
        encode_u8(buf, self.sm_length);

        // short_message (variable length, not null terminated)
        buf.extend_from_slice(self.short_message.as_bytes());

        // Optional TLV parameters
        for tlv in &self.optional_parameters {
            tlv.encode(buf)?;
        }

        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = 16 + 6 + 1 + 1 + 21 + 1; // header + fixed fields up to number_of_dests

        // Add destination addresses size
        for dest_addr in &self.dest_addresses {
            size += dest_addr.encoded_size();
        }

        size += 1 + 1 + 1 + 17 + 17 + 1 + 1 + 1 + 1; // remaining fixed fields
        size += self.short_message.len() as usize; // variable message content

        // Add TLV sizes
        for tlv in &self.optional_parameters {
            size += tlv.encoded_size();
        }

        size
    }
}

impl Decodable for SubmitMulti {
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

        let number_of_dests = decode_u8(buf)?;

        // Decode destination addresses
        let mut dest_addresses = Vec::new();
        for _i in 0..number_of_dests {
            let dest_addr = DestinationAddress::decode(buf)?;
            dest_addresses.push(dest_addr);
        }

        let esm_class_byte = decode_u8(buf)?;
        let esm_class = EsmClass::from_byte(esm_class_byte).map_err(|e| {
            CodecError::FieldValidation {
                field: "esm_class",
                reason: format!("{e}"),
            }
        })?;

        let protocol_id = decode_u8(buf)?;

        let priority_flag =
            PriorityFlag::try_from(decode_u8(buf)?).map_err(|_| CodecError::FieldValidation {
                field: "priority_flag",
                reason: "Invalid PriorityFlag value".to_string(),
            })?;

        let schedule_delivery_time_str = decode_cstring(buf, 17, "schedule_delivery_time")?;
        let schedule_delivery_time = ScheduleDeliveryTime::new(&schedule_delivery_time_str)
            .map_err(|e| CodecError::FieldValidation {
                field: "schedule_delivery_time",
                reason: format!("{e}"),
            })?;

        let validity_period_str = decode_cstring(buf, 17, "validity_period")?;
        let validity_period =
            ValidityPeriod::new(&validity_period_str).map_err(|e| CodecError::FieldValidation {
                field: "validity_period",
                reason: format!("{e}"),
            })?;

        let registered_delivery = decode_u8(buf)?;
        let replace_if_present_flag = decode_u8(buf)?;

        let data_coding_byte = decode_u8(buf)?;
        let data_coding = DataCoding::from_byte(data_coding_byte);

        let sm_default_msg_id = decode_u8(buf)?;
        let sm_length = decode_u8(buf)?;

        // Read short_message (variable length based on sm_length)
        if buf.remaining() < sm_length as usize {
            return Err(CodecError::Incomplete);
        }
        let mut short_message_bytes = vec![0u8; sm_length as usize];
        for byte in short_message_bytes.iter_mut().take(sm_length as usize) {
            *byte = decode_u8(buf)?;
        }
        let short_message =
            ShortMessage::new(&short_message_bytes).map_err(|e| CodecError::FieldValidation {
                field: "short_message",
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

        Ok(SubmitMulti {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            service_type,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            number_of_dests,
            dest_addresses,
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
            optional_parameters,
        })
    }

    fn command_id() -> CommandId {
        CommandId::SubmitMulti
    }
}

/// Validation errors for SubmitMultiResponse PDU
#[derive(Debug, Error)]
pub enum SubmitMultiResponseValidationError {
    #[error("Message ID error: {0}")]
    MessageId(#[from] FixedStringError),
    #[error("Too many unsuccess addresses: {count}, maximum allowed: {max}")]
    TooManyUnsuccessAddresses { count: usize, max: usize },
    #[error("Unsuccess address count mismatch: no_unsuccess {no_unsuccess} does not match actual count {actual_count}")]
    UnsuccessCountMismatch { no_unsuccess: u8, actual_count: usize },
}

/// Unsuccessful delivery address information
#[derive(Clone, Debug, PartialEq)]
pub struct UnsuccessSmeAddress {
    /// Type of Number for destination address
    pub dest_addr_ton: TypeOfNumber,
    /// Numbering Plan Indicator for destination address  
    pub dest_addr_npi: NumericPlanIndicator,
    /// Destination address that failed
    pub destination_addr: String,
    /// Error status code for this address
    pub error_status_code: CommandStatus,
}

impl UnsuccessSmeAddress {
    /// Create a new unsuccessful SME address entry
    pub fn new(
        dest_addr_ton: TypeOfNumber,
        dest_addr_npi: NumericPlanIndicator,
        destination_addr: &str,
        error_status_code: CommandStatus,
    ) -> Self {
        UnsuccessSmeAddress {
            dest_addr_ton,
            dest_addr_npi,
            destination_addr: destination_addr.to_string(),
            error_status_code,
        }
    }

    /// Encode this unsuccessful address to buffer
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        encode_u8(buf, self.dest_addr_ton as u8);
        encode_u8(buf, self.dest_addr_npi as u8);
        // Variable-length null-terminated string
        buf.extend_from_slice(self.destination_addr.as_bytes());
        buf.put_u8(0); // null terminator
        buf.put_u32(self.error_status_code as u32);
        Ok(())
    }

    /// Decode an unsuccessful address from buffer
    pub fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let dest_addr_ton = TypeOfNumber::try_from(decode_u8(buf)?).map_err(|_| {
            CodecError::FieldValidation {
                field: "dest_addr_ton",
                reason: "Invalid TypeOfNumber value".to_string(),
            }
        })?;

        let dest_addr_npi = NumericPlanIndicator::try_from(decode_u8(buf)?).map_err(|_| {
            CodecError::FieldValidation {
                field: "dest_addr_npi",
                reason: "Invalid NumericPlanIndicator value".to_string(),
            }
        })?;

        let destination_addr = decode_null_terminated_string(buf, "destination_addr")?;
        let error_status_code = CommandStatus::try_from(buf.get_u32()).map_err(|_| {
            CodecError::FieldValidation {
                field: "error_status_code",
                reason: "Invalid CommandStatus value".to_string(),
            }
        })?;

        Ok(UnsuccessSmeAddress {
            dest_addr_ton,
            dest_addr_npi,
            destination_addr,
            error_status_code,
        })
    }

    /// Calculate the encoded size of this unsuccessful address
    pub fn encoded_size(&self) -> usize {
        1 + 1 + self.destination_addr.len() + 1 + 4 // ton + npi + addr + null + error_status
    }
}

/// SMPP v3.4 submit_multi_resp PDU (Section 4.4.2)
///
/// The submit_multi_resp PDU is used to return the result of a submit_multi request.
/// If the message was accepted for delivery to all destinations, only the message_id
/// is returned. If some destinations failed, the response includes detailed error
/// information for each failed destination.
///
/// ## Mandatory Parameters
/// - message_id: Message ID assigned by SMSC (if any destinations succeeded)
/// - no_unsuccess: Number of unsuccessful destination addresses
/// - unsuccess_sme: List of unsuccessful SME addresses with error codes
///
/// ## References
/// - SMPP v3.4 Specification Section 4.4.2
#[derive(Clone, Debug, PartialEq)]
pub struct SubmitMultiResponse {
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Mandatory parameters
    /// Message ID assigned by the SMSC.
    /// Set to empty string if all destinations failed.
    pub message_id: MessageId,

    /// Number of unsuccessful destination addresses.
    /// Set to 0 if all destinations were successful.
    pub no_unsuccess: u8,

    /// List of unsuccessful SME addresses with error information.
    /// Only populated if no_unsuccess > 0.
    pub unsuccess_sme: Vec<UnsuccessSmeAddress>,
}

impl SubmitMultiResponse {
    /// Maximum number of unsuccessful addresses that can be reported
    pub const MAX_UNSUCCESS_ADDRESSES: usize = 255;

    /// Create a new SubmitMultiResponse PDU
    pub fn new(
        sequence_number: u32,
        command_status: CommandStatus,
        message_id: MessageId,
        unsuccess_sme: Vec<UnsuccessSmeAddress>,
    ) -> Result<Self, SubmitMultiResponseValidationError> {
        if unsuccess_sme.len() > Self::MAX_UNSUCCESS_ADDRESSES {
            return Err(SubmitMultiResponseValidationError::TooManyUnsuccessAddresses {
                count: unsuccess_sme.len(),
                max: Self::MAX_UNSUCCESS_ADDRESSES,
            });
        }

        let no_unsuccess = unsuccess_sme.len() as u8;

        let pdu = SubmitMultiResponse {
            command_status,
            sequence_number,
            message_id,
            no_unsuccess,
            unsuccess_sme,
        };

        // Validate the PDU
        pdu.validate()?;
        Ok(pdu)
    }

    /// Create a successful SubmitMultiResponse (all destinations succeeded)
    pub fn success(sequence_number: u32, message_id: MessageId) -> Self {
        SubmitMultiResponse {
            command_status: CommandStatus::Ok,
            sequence_number,
            message_id,
            no_unsuccess: 0,
            unsuccess_sme: Vec::new(),
        }
    }

    /// Create a complete failure SubmitMultiResponse (all destinations failed)
    pub fn complete_failure(sequence_number: u32, command_status: CommandStatus) -> Self {
        SubmitMultiResponse {
            command_status,
            sequence_number,
            message_id: MessageId::new(b"").unwrap_or_else(|_| MessageId::new(b"ERROR").unwrap()),
            no_unsuccess: 0, // No specific unsuccessful addresses for complete failure
            unsuccess_sme: Vec::new(),
        }
    }

    /// Create a partial success SubmitMultiResponse (some destinations failed)
    pub fn partial_success(
        sequence_number: u32,
        message_id: MessageId,
        unsuccess_sme: Vec<UnsuccessSmeAddress>,
    ) -> Result<Self, SubmitMultiResponseValidationError> {
        Self::new(sequence_number, CommandStatus::Ok, message_id, unsuccess_sme)
    }

    /// Add an unsuccessful address to the response
    pub fn add_unsuccessful_address(
        &mut self,
        dest_addr_ton: TypeOfNumber,
        dest_addr_npi: NumericPlanIndicator,
        destination_addr: &str,
        error_status_code: CommandStatus,
    ) -> Result<(), SubmitMultiResponseValidationError> {
        if self.unsuccess_sme.len() >= Self::MAX_UNSUCCESS_ADDRESSES {
            return Err(SubmitMultiResponseValidationError::TooManyUnsuccessAddresses {
                count: self.unsuccess_sme.len() + 1,
                max: Self::MAX_UNSUCCESS_ADDRESSES,
            });
        }

        let unsuccess_addr = UnsuccessSmeAddress::new(
            dest_addr_ton,
            dest_addr_npi,
            destination_addr,
            error_status_code,
        );
        self.unsuccess_sme.push(unsuccess_addr);
        self.no_unsuccess = self.unsuccess_sme.len() as u8;
        Ok(())
    }

    /// Check if all destinations were successful
    pub fn is_complete_success(&self) -> bool {
        self.command_status == CommandStatus::Ok && self.no_unsuccess == 0
    }

    /// Check if all destinations failed
    pub fn is_complete_failure(&self) -> bool {
        self.command_status != CommandStatus::Ok && self.no_unsuccess == 0
    }

    /// Check if some destinations succeeded and some failed
    pub fn is_partial_success(&self) -> bool {
        self.command_status == CommandStatus::Ok && self.no_unsuccess > 0
    }

    /// Get the number of unsuccessful destinations
    pub fn unsuccessful_count(&self) -> usize {
        self.unsuccess_sme.len()
    }

    /// Validate the SubmitMultiResponse PDU
    fn validate(&self) -> Result<(), SubmitMultiResponseValidationError> {
        // Validate unsuccess count consistency
        if self.no_unsuccess as usize != self.unsuccess_sme.len() {
            return Err(SubmitMultiResponseValidationError::UnsuccessCountMismatch {
                no_unsuccess: self.no_unsuccess,
                actual_count: self.unsuccess_sme.len(),
            });
        }

        // Other validations are handled by the respective data types
        Ok(())
    }
}

impl Encodable for SubmitMultiResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // PDU Header (will be filled by codec)
        buf.put_u32(0); // command_length (placeholder)
        buf.put_u32(CommandId::SubmitMultiResp as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Mandatory parameters
        // message_id (65 octets, null-terminated with padding)
        encode_cstring(buf, self.message_id.as_str().unwrap_or(""), 65);

        // no_unsuccess (1 octet)
        encode_u8(buf, self.no_unsuccess);

        // unsuccess_sme (variable length)
        for unsuccess_addr in &self.unsuccess_sme {
            unsuccess_addr.encode(buf)?;
        }

        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = 16 + 65 + 1; // header + message_id + no_unsuccess

        // Add unsuccessful addresses size
        for unsuccess_addr in &self.unsuccess_sme {
            size += unsuccess_addr.encoded_size();
        }

        size
    }
}

impl Decodable for SubmitMultiResponse {
    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory parameters
        let message_id_str = decode_cstring(buf, 65, "message_id")?;
        let message_id =
            MessageId::new(message_id_str.as_bytes()).map_err(|e| CodecError::FieldValidation {
                field: "message_id",
                reason: format!("{e}"),
            })?;

        let no_unsuccess = decode_u8(buf)?;

        // Decode unsuccessful SME addresses
        let mut unsuccess_sme = Vec::new();
        for _i in 0..no_unsuccess {
            let unsuccess_addr = UnsuccessSmeAddress::decode(buf)?;
            unsuccess_sme.push(unsuccess_addr);
        }

        Ok(SubmitMultiResponse {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            message_id,
            no_unsuccess,
            unsuccess_sme,
        })
    }

    fn command_id() -> CommandId {
        CommandId::SubmitMultiResp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datatypes::{NumericPlanIndicator, TypeOfNumber};

    #[test]
    fn test_destination_address_sme() {
        let dest_addr = DestinationAddress::sme_address(
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            "1234567890",
        )
        .unwrap();

        assert_eq!(dest_addr.dest_flag(), 1);
        if let DestinationAddress::SmeAddress { destination_addr, .. } = dest_addr {
            assert_eq!(destination_addr, "1234567890");
        } else {
            panic!("Expected SME address");
        }
    }

    #[test]
    fn test_destination_address_distribution_list() {
        let dest_addr = DestinationAddress::distribution_list("FRIENDS").unwrap();

        assert_eq!(dest_addr.dest_flag(), 2);
        if let DestinationAddress::DistributionList { dl_name, .. } = dest_addr {
            assert_eq!(dl_name, "FRIENDS");
        } else {
            panic!("Expected distribution list");
        }
    }

    #[test]
    fn test_submit_multi_creation() {
        let service_type = ServiceType::new("").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let short_message = ShortMessage::new(b"Hello everyone!").unwrap();
        let esm_class = EsmClass::default();
        let data_coding = DataCoding::default();

        let dest_addresses = vec![
            DestinationAddress::sme_address(
                TypeOfNumber::International,
                NumericPlanIndicator::Isdn,
                "0987654321",
            ).unwrap(),
            DestinationAddress::distribution_list("BROADCAST").unwrap(),
        ];

        let submit_multi = SubmitMulti::new(
            123,
            service_type,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            dest_addresses,
            esm_class,
            0x00, // protocol_id
            PriorityFlag::Level0,
            ScheduleDeliveryTime::new("").unwrap(),
            ValidityPeriod::new("").unwrap(),
            0x01, // registered_delivery
            0x00, // replace_if_present_flag
            data_coding,
            0x00, // sm_default_msg_id
            short_message,
        )
        .unwrap();

        assert_eq!(submit_multi.sequence_number, 123);
        assert_eq!(submit_multi.command_status, CommandStatus::Ok);
        assert_eq!(submit_multi.number_of_dests, 2);
        assert_eq!(submit_multi.dest_addresses.len(), 2);
        assert_eq!(submit_multi.sm_length, 15); // "Hello everyone!" length
    }

    #[test]
    fn test_submit_multi_encoding_decoding() {
        let service_type = ServiceType::new("SMS").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let short_message = ShortMessage::new(b"Test message").unwrap();
        let esm_class = EsmClass::default();
        let data_coding = DataCoding::default();

        let dest_addresses = vec![
            DestinationAddress::sme_address(
                TypeOfNumber::International,
                NumericPlanIndicator::Isdn,
                "0987654321",
            ).unwrap(),
        ];

        let original = SubmitMulti::new(
            456,
            service_type,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            dest_addresses,
            esm_class,
            0x00,
            PriorityFlag::Level0,
            ScheduleDeliveryTime::new("").unwrap(),
            ValidityPeriod::new("").unwrap(),
            0x01,
            0x00,
            data_coding,
            0x00,
            short_message,
        )
        .unwrap();

        // Test encoding
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Test decoding
        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::SubmitMulti,
            command_status: CommandStatus::Ok,
            sequence_number: 456,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = SubmitMulti::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_submit_multi_response_success() {
        let message_id = MessageId::new(b"MSG12345").unwrap();
        let response = SubmitMultiResponse::success(789, message_id);

        assert_eq!(response.sequence_number, 789);
        assert_eq!(response.command_status, CommandStatus::Ok);
        assert_eq!(response.message_id.as_str().unwrap(), "MSG12345");
        assert_eq!(response.no_unsuccess, 0);
        assert!(response.unsuccess_sme.is_empty());
        assert!(response.is_complete_success());
    }

    #[test]
    fn test_submit_multi_response_partial_success() {
        let message_id = MessageId::new(b"MSG67890").unwrap();
        let unsuccess_addresses = vec![
            UnsuccessSmeAddress::new(
                TypeOfNumber::International,
                NumericPlanIndicator::Isdn,
                "1111111111",
                CommandStatus::InvalidDestinationAddress,
            ),
        ];

        let response = SubmitMultiResponse::partial_success(999, message_id, unsuccess_addresses).unwrap();

        assert_eq!(response.sequence_number, 999);
        assert_eq!(response.command_status, CommandStatus::Ok);
        assert_eq!(response.no_unsuccess, 1);
        assert_eq!(response.unsuccess_sme.len(), 1);
        assert!(response.is_partial_success());
        assert_eq!(response.unsuccess_sme[0].destination_addr, "1111111111");
        assert_eq!(response.unsuccess_sme[0].error_status_code, CommandStatus::InvalidDestinationAddress);
    }

    #[test]
    fn test_submit_multi_response_complete_failure() {
        let response = SubmitMultiResponse::complete_failure(555, CommandStatus::MessageQueueFull);

        assert_eq!(response.sequence_number, 555);
        assert_eq!(response.command_status, CommandStatus::MessageQueueFull);
        assert_eq!(response.no_unsuccess, 0);
        assert!(response.unsuccess_sme.is_empty());
        assert!(response.is_complete_failure());
    }

    #[test]
    fn test_submit_multi_response_encoding_decoding() {
        let message_id = MessageId::new(b"TEST001").unwrap();
        let original = SubmitMultiResponse::success(777, message_id);

        // Test encoding
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Test decoding
        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::SubmitMultiResp,
            command_status: CommandStatus::Ok,
            sequence_number: 777,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = SubmitMultiResponse::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_submit_multi_max_destinations() {
        let service_type = ServiceType::new("").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let short_message = ShortMessage::new(b"Test").unwrap();
        let esm_class = EsmClass::default();
        let data_coding = DataCoding::default();

        // Create 255 destinations (maximum allowed)
        let mut dest_addresses = Vec::new();
        for i in 0..255 {
            dest_addresses.push(
                DestinationAddress::sme_address(
                    TypeOfNumber::International,
                    NumericPlanIndicator::Isdn,
                    &format!("100{:07}", i),
                ).unwrap()
            );
        }

        let submit_multi = SubmitMulti::new(
            100,
            service_type,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            dest_addresses,
            esm_class,
            0x00,
            PriorityFlag::Level0,
            ScheduleDeliveryTime::new("").unwrap(),
            ValidityPeriod::new("").unwrap(),
            0x00,
            0x00,
            data_coding,
            0x00,
            short_message,
        )
        .unwrap();

        assert_eq!(submit_multi.number_of_dests, 255);
        assert_eq!(submit_multi.destination_count(), 255);
        assert!(submit_multi.is_at_capacity());
    }

    #[test]
    fn test_submit_multi_too_many_destinations() {
        let service_type = ServiceType::new("").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let short_message = ShortMessage::new(b"Test").unwrap();
        let esm_class = EsmClass::default();
        let data_coding = DataCoding::default();

        // Try to create 256 destinations (too many)
        let mut dest_addresses = Vec::new();
        for i in 0..256 {
            dest_addresses.push(
                DestinationAddress::sme_address(
                    TypeOfNumber::International,
                    NumericPlanIndicator::Isdn,
                    &format!("100{:07}", i),
                ).unwrap()
            );
        }

        let result = SubmitMulti::new(
            100,
            service_type,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            dest_addresses,
            esm_class,
            0x00,
            PriorityFlag::Level0,
            ScheduleDeliveryTime::new("").unwrap(),
            ValidityPeriod::new("").unwrap(),
            0x00,
            0x00,
            data_coding,
            0x00,
            short_message,
        );

        assert!(result.is_err());
        if let Err(SubmitMultiValidationError::TooManyDestinations { count, max }) = result {
            assert_eq!(count, 256);
            assert_eq!(max, 255);
        } else {
            panic!("Expected TooManyDestinations error");
        }
    }
}