// ABOUTME: Implements SMPP v3.4 cancel_sm and cancel_sm_resp PDUs for message cancellation
// ABOUTME: Provides message cancellation functionality per specification Section 4.10

use crate::datatypes::{
    AddressError, CommandId, CommandStatus, FixedStringError, MessageId, NumericPlanIndicator,
    ServiceType, SourceAddr, TypeOfNumber,
};
use bytes::{BufMut, BytesMut};
use std::io::Cursor;
use thiserror::Error;

// Import codec traits
use crate::codec::{
    CodecError, Decodable, Encodable, PduHeader, decode_cstring, decode_u8, encode_cstring,
    encode_u8,
};

/// Validation errors for CancelSm PDU
#[derive(Debug, Error)]
pub enum CancelSmValidationError {
    #[error("Service type error: {0}")]
    ServiceType(#[from] crate::datatypes::ServiceTypeError),
    #[error("Message ID error: {0}")]
    MessageId(#[from] FixedStringError),
    #[error("Source address error: {0}")]
    SourceAddr(#[from] AddressError),
}

/// SMPP v3.4 cancel_sm PDU (Section 4.10.1)
///
/// The cancel_sm operation is used by an ESME to cancel a previously submitted short message
/// that is still pending delivery. The matching algorithm used to find the message to cancel
/// is implementation specific, but must include matching of the source address and message_id.
///
/// ## Mandatory Parameters
/// - service_type: The service_type parameter can be used to indicate the SMS Application service
/// - message_id: Message ID of the message to be cancelled
/// - source_addr_ton: Type of Number of message originator  
/// - source_addr_npi: Numbering Plan Indicator of message originator
/// - source_addr: Address of message originator
/// - dest_addr_ton: Type of Number for destination
/// - dest_addr_npi: Numbering Plan Indicator for destination
/// - destination_addr: Destination address of the message to be cancelled
///
/// ## References
/// - SMPP v3.4 Specification Section 4.10.1
#[derive(Clone, Debug, PartialEq)]
pub struct CancelSm {
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Mandatory parameters
    /// The service_type parameter can be used to indicate the SMS Application service
    /// associated with the message. Set to NULL for default SMSC settings.
    pub service_type: ServiceType,

    /// Message ID of the message to be cancelled.
    /// This should match the message_id returned in the original submit_sm_resp PDU.
    pub message_id: MessageId,

    /// Type of Number of message originator.
    /// Should match the source_addr_ton used in the original submit_sm.
    pub source_addr_ton: TypeOfNumber,

    /// Numbering Plan Indicator of message originator.
    /// Should match the source_addr_npi used in the original submit_sm.
    pub source_addr_npi: NumericPlanIndicator,

    /// Address of message originator.
    /// Should match the source_addr used in the original submit_sm.
    pub source_addr: SourceAddr,

    /// Type of Number for destination.
    /// Should match the dest_addr_ton used in the original submit_sm.
    pub dest_addr_ton: TypeOfNumber,

    /// Numbering Plan Indicator for destination.
    /// Should match the dest_addr_npi used in the original submit_sm.
    pub dest_addr_npi: NumericPlanIndicator,

    /// Destination address of the message to be cancelled.
    /// Should match the destination_addr used in the original submit_sm.
    pub destination_addr: SourceAddr, // Reusing SourceAddr type for destination
}

impl CancelSm {
    /// Create a new CancelSm PDU
    pub fn new(
        sequence_number: u32,
        service_type: ServiceType,
        message_id: MessageId,
        source_addr_ton: TypeOfNumber,
        source_addr_npi: NumericPlanIndicator,
        source_addr: SourceAddr,
        dest_addr_ton: TypeOfNumber,
        dest_addr_npi: NumericPlanIndicator,
        destination_addr: SourceAddr,
    ) -> Result<Self, CancelSmValidationError> {
        let pdu = CancelSm {
            command_status: CommandStatus::Ok, // Always 0 for requests
            sequence_number,
            service_type,
            message_id,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            dest_addr_ton,
            dest_addr_npi,
            destination_addr,
        };

        // Validate the PDU
        pdu.validate()?;
        Ok(pdu)
    }

    /// Validate the CancelSm PDU
    fn validate(&self) -> Result<(), CancelSmValidationError> {
        // service_type validation is handled by ServiceType type
        // message_id validation is handled by MessageId type
        // source_addr validation is handled by SourceAddr type
        // destination_addr validation is handled by SourceAddr type
        Ok(())
    }
}

impl Encodable for CancelSm {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // PDU Header (will be filled by codec)
        buf.put_u32(0); // command_length (placeholder)
        buf.put_u32(CommandId::CancelSm as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Mandatory parameters
        // service_type (6 octets, null-terminated with padding)
        encode_cstring(buf, self.service_type.as_str(), 6);

        // message_id (65 octets, null-terminated with padding)
        encode_cstring(buf, self.message_id.as_str().unwrap_or(""), 65);

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

        Ok(())
    }
}

impl Decodable for CancelSm {
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

        let message_id_str = decode_cstring(buf, 65, "message_id")?;
        let message_id =
            MessageId::new(message_id_str.as_bytes()).map_err(|e| CodecError::FieldValidation {
                field: "message_id",
                reason: format!("{e}"),
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
        let destination_addr = SourceAddr::new(&destination_addr_str, dest_addr_ton).map_err(|e| {
            CodecError::FieldValidation {
                field: "destination_addr",
                reason: format!("{e}"),
            }
        })?;

        Ok(CancelSm {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            service_type,
            message_id,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            dest_addr_ton,
            dest_addr_npi,
            destination_addr,
        })
    }

    fn command_id() -> CommandId {
        CommandId::CancelSm
    }
}

/// Validation errors for CancelSmResponse PDU
#[derive(Debug, Error)]
pub enum CancelSmResponseValidationError {
    // This PDU has no additional validation beyond the standard header validation
}

/// SMPP v3.4 cancel_sm_resp PDU (Section 4.10.2)
///
/// The cancel_sm_resp PDU is used to return the result of a cancel_sm request.
/// This PDU contains no mandatory parameters beyond the standard PDU header.
///
/// ## References
/// - SMPP v3.4 Specification Section 4.10.2
#[derive(Clone, Debug, PartialEq)]
pub struct CancelSmResponse {
    pub command_status: CommandStatus,
    pub sequence_number: u32,
    // No additional mandatory parameters
}

impl CancelSmResponse {
    /// Create a new CancelSmResponse PDU
    pub fn new(
        sequence_number: u32,
        command_status: CommandStatus,
    ) -> Result<Self, CancelSmResponseValidationError> {
        let pdu = CancelSmResponse {
            command_status,
            sequence_number,
        };

        // Validate the PDU
        pdu.validate()?;
        Ok(pdu)
    }

    /// Create a successful CancelSmResponse
    pub fn success(sequence_number: u32) -> Self {
        CancelSmResponse {
            command_status: CommandStatus::Ok,
            sequence_number,
        }
    }

    /// Create an error CancelSmResponse
    pub fn error(sequence_number: u32, command_status: CommandStatus) -> Self {
        CancelSmResponse {
            command_status,
            sequence_number,
        }
    }

    /// Validate the CancelSmResponse PDU
    fn validate(&self) -> Result<(), CancelSmResponseValidationError> {
        // No additional validation needed
        Ok(())
    }
}

impl Encodable for CancelSmResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // PDU Header (will be filled by codec)
        buf.put_u32(0); // command_length (placeholder)
        buf.put_u32(CommandId::CancelSmResp as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // No additional mandatory parameters
        Ok(())
    }
}

impl Decodable for CancelSmResponse {
    fn decode(header: PduHeader, _buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // No additional parameters to decode
        Ok(CancelSmResponse {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
        })
    }

    fn command_id() -> CommandId {
        CommandId::CancelSmResp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datatypes::{NumericPlanIndicator, TypeOfNumber};

    #[test]
    fn test_cancel_sm_creation() {
        let service_type = ServiceType::new("").unwrap();
        let message_id = MessageId::new(b"12345678").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let destination_addr = SourceAddr::new("0987654321", TypeOfNumber::International).unwrap();

        let cancel_sm = CancelSm::new(
            123,
            service_type,
            message_id,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            destination_addr,
        )
        .unwrap();

        assert_eq!(cancel_sm.sequence_number, 123);
        assert_eq!(cancel_sm.command_status, CommandStatus::Ok);
        assert_eq!(cancel_sm.service_type.as_str(), "");
        assert_eq!(cancel_sm.message_id.as_str().unwrap(), "12345678");
        assert_eq!(cancel_sm.source_addr_ton, TypeOfNumber::International);
        assert_eq!(cancel_sm.source_addr_npi, NumericPlanIndicator::Isdn);
        assert_eq!(cancel_sm.source_addr.as_str().unwrap(), "1234567890");
        assert_eq!(cancel_sm.dest_addr_ton, TypeOfNumber::International);
        assert_eq!(cancel_sm.dest_addr_npi, NumericPlanIndicator::Isdn);
        assert_eq!(cancel_sm.destination_addr.as_str().unwrap(), "0987654321");
    }

    #[test]
    fn test_cancel_sm_encoding_decoding() {
        let service_type = ServiceType::new("SMS").unwrap();
        let message_id = MessageId::new(b"MSG001").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let destination_addr = SourceAddr::new("0987654321", TypeOfNumber::International).unwrap();

        let original = CancelSm::new(
            456,
            service_type,
            message_id,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            destination_addr,
        )
        .unwrap();

        // Test encoding
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Test decoding
        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::CancelSm,
            command_status: CommandStatus::Ok,
            sequence_number: 456,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = CancelSm::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_cancel_sm_response_creation() {
        let response = CancelSmResponse::new(789, CommandStatus::Ok).unwrap();

        assert_eq!(response.sequence_number, 789);
        assert_eq!(response.command_status, CommandStatus::Ok);
    }

    #[test]
    fn test_cancel_sm_response_success() {
        let response = CancelSmResponse::success(456);

        assert_eq!(response.sequence_number, 456);
        assert_eq!(response.command_status, CommandStatus::Ok);
    }

    #[test]
    fn test_cancel_sm_response_error() {
        let response = CancelSmResponse::error(789, CommandStatus::InvalidMessageId);

        assert_eq!(response.sequence_number, 789);
        assert_eq!(response.command_status, CommandStatus::InvalidMessageId);
    }

    #[test]
    fn test_cancel_sm_response_encoding_decoding() {
        let original = CancelSmResponse::success(999);

        // Test encoding
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Test decoding
        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::CancelSmResp,
            command_status: CommandStatus::Ok,
            sequence_number: 999,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = CancelSmResponse::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_cancel_sm_with_service_type() {
        let service_type = ServiceType::new("WAP").unwrap();
        let message_id = MessageId::new(b"MSG003").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let destination_addr = SourceAddr::new("0987654321", TypeOfNumber::National).unwrap();

        let cancel_sm = CancelSm::new(
            111,
            service_type,
            message_id,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::National,
            NumericPlanIndicator::Isdn,
            destination_addr,
        )
        .unwrap();

        assert_eq!(cancel_sm.service_type.as_str(), "WAP");
        assert_eq!(cancel_sm.dest_addr_ton, TypeOfNumber::National);

        // Test encoding/decoding with different service type
        let mut buf = BytesMut::new();
        cancel_sm.encode(&mut buf).unwrap();

        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::CancelSm,
            command_status: CommandStatus::Ok,
            sequence_number: 111,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = CancelSm::decode(header, &mut cursor).unwrap();

        assert_eq!(cancel_sm, decoded);
    }

    #[test]
    fn test_cancel_sm_mixed_addressing() {
        let service_type = ServiceType::new("").unwrap();
        let message_id = MessageId::new(b"MIXED001").unwrap();
        let source_addr = SourceAddr::new("12345", TypeOfNumber::National).unwrap();
        let destination_addr = SourceAddr::new("+1234567890", TypeOfNumber::International).unwrap();

        let cancel_sm = CancelSm::new(
            222,
            service_type,
            message_id,
            TypeOfNumber::National,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            destination_addr,
        )
        .unwrap();

        // Test that mixed addressing modes work correctly
        assert_eq!(cancel_sm.source_addr_ton, TypeOfNumber::National);
        assert_eq!(cancel_sm.dest_addr_ton, TypeOfNumber::International);
        assert_eq!(cancel_sm.source_addr.as_str().unwrap(), "12345");
        assert_eq!(cancel_sm.destination_addr.as_str().unwrap(), "+1234567890");

        // Test encoding/decoding preserves mixed addressing
        let mut buf = BytesMut::new();
        cancel_sm.encode(&mut buf).unwrap();

        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::CancelSm,
            command_status: CommandStatus::Ok,
            sequence_number: 222,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = CancelSm::decode(header, &mut cursor).unwrap();

        assert_eq!(cancel_sm, decoded);
    }
}