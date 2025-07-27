// ABOUTME: Implements SMPP v3.4 replace_sm and replace_sm_resp PDUs for message replacement
// ABOUTME: Provides message replacement functionality per specification Section 4.9

use crate::datatypes::{
    AddressError, CommandId, CommandStatus, FixedStringError, MessageId, NumericPlanIndicator,
    ScheduleDeliveryTime, ShortMessage, SourceAddr, TypeOfNumber, ValidityPeriod,
};
use bytes::{Buf, BufMut, BytesMut};
use std::io::Cursor;
use thiserror::Error;

// Import codec traits
use crate::codec::{
    CodecError, Decodable, Encodable, PduHeader, decode_cstring, decode_u8, encode_cstring,
    encode_u8,
};

/// Validation errors for ReplaceSm PDU
#[derive(Debug, Error)]
pub enum ReplaceSmValidationError {
    #[error("Message ID error: {0}")]
    MessageId(#[from] FixedStringError),
    #[error("Source address error: {0}")]
    SourceAddr(#[from] AddressError),
}

/// SMPP v3.4 replace_sm PDU (Section 4.9.1)
///
/// The replace_sm operation is used by an ESME to replace a previously submitted short message
/// that is still pending delivery. The matching algorithm used to find the message to replace
/// is implementation specific, but must include matching of the source address and message_id.
///
/// ## Mandatory Parameters
/// - message_id: Message ID of the message to be replaced
/// - source_addr_ton: Type of Number of message originator  
/// - source_addr_npi: Numbering Plan Indicator of message originator
/// - source_addr: Address of message originator
/// - schedule_delivery_time: Scheduled delivery time for the replacement message
/// - validity_period: Validity period for the replacement message
/// - registered_delivery: Registered delivery flag for the replacement message
/// - sm_default_msg_id: Default message ID for replacement message
/// - sm_length: Length of replacement short message
/// - short_message: Replacement short message content
///
/// ## References
/// - SMPP v3.4 Specification Section 4.9.1
#[derive(Clone, Debug, PartialEq)]
pub struct ReplaceSm {
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Mandatory parameters
    /// Message ID of the message to be replaced.
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

    /// Scheduled delivery time for the replacement message.
    /// Set to NULL for immediate delivery.
    pub schedule_delivery_time: ScheduleDeliveryTime,

    /// Validity period for the replacement message.
    /// Set to NULL to request the SMSC default validity period.
    pub validity_period: ValidityPeriod,

    /// Registered delivery flag for the replacement message.
    /// Indicates if delivery receipt is requested.
    pub registered_delivery: u8,

    /// Default message ID for replacement message.
    /// Used when the short message is replaced by a predefined message.
    pub sm_default_msg_id: u8,

    /// Length of replacement short message.
    /// Must match the actual length of the short_message field.
    pub sm_length: u8,

    /// Replacement short message content.
    /// The new message text that will replace the original message.
    pub short_message: ShortMessage,
}

impl ReplaceSm {
    /// Create a new ReplaceSm PDU
    pub fn new(
        sequence_number: u32,
        message_id: MessageId,
        source_addr_ton: TypeOfNumber,
        source_addr_npi: NumericPlanIndicator,
        source_addr: SourceAddr,
        schedule_delivery_time: ScheduleDeliveryTime,
        validity_period: ValidityPeriod,
        registered_delivery: u8,
        sm_default_msg_id: u8,
        short_message: ShortMessage,
    ) -> Result<Self, ReplaceSmValidationError> {
        let sm_length = short_message.len();

        let pdu = ReplaceSm {
            command_status: CommandStatus::Ok, // Always 0 for requests
            sequence_number,
            message_id,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            schedule_delivery_time,
            validity_period,
            registered_delivery,
            sm_default_msg_id,
            sm_length,
            short_message,
        };

        // Validate the PDU
        pdu.validate()?;
        Ok(pdu)
    }

    /// Validate the ReplaceSm PDU
    fn validate(&self) -> Result<(), ReplaceSmValidationError> {
        // message_id validation is handled by MessageId type
        // source_addr validation is handled by SourceAddr type
        // sm_length consistency is enforced by constructor
        Ok(())
    }
}

impl Encodable for ReplaceSm {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // PDU Header (will be filled by codec)
        buf.put_u32(0); // command_length (placeholder)
        buf.put_u32(CommandId::ReplaceSm as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Mandatory parameters
        // message_id (65 octets, null-terminated with padding)
        encode_cstring(buf, self.message_id.as_str().unwrap_or(""), 65);

        // source_addr_ton (1 octet)
        encode_u8(buf, self.source_addr_ton as u8);

        // source_addr_npi (1 octet)
        encode_u8(buf, self.source_addr_npi as u8);

        // source_addr (21 octets, null-terminated with padding)
        encode_cstring(buf, self.source_addr.as_str().unwrap_or(""), 21);

        // schedule_delivery_time (17 octets, null-terminated with padding)
        encode_cstring(buf, self.schedule_delivery_time.as_str().unwrap_or(""), 17);

        // validity_period (17 octets, null-terminated with padding)
        encode_cstring(buf, self.validity_period.as_str().unwrap_or(""), 17);

        // registered_delivery (1 octet)
        encode_u8(buf, self.registered_delivery);

        // sm_default_msg_id (1 octet)
        encode_u8(buf, self.sm_default_msg_id);

        // sm_length (1 octet)
        encode_u8(buf, self.sm_length);

        // short_message (variable length, not null terminated)
        buf.extend_from_slice(self.short_message.as_bytes());

        Ok(())
    }
}

impl Decodable for ReplaceSm {
    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory parameters
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

        Ok(ReplaceSm {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            message_id,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            schedule_delivery_time,
            validity_period,
            registered_delivery,
            sm_default_msg_id,
            sm_length,
            short_message,
        })
    }

    fn command_id() -> CommandId {
        CommandId::ReplaceSm
    }
}

/// Validation errors for ReplaceSmResponse PDU
#[derive(Debug, Error)]
pub enum ReplaceSmResponseValidationError {
    // This PDU has no additional validation beyond the standard header validation
}

/// SMPP v3.4 replace_sm_resp PDU (Section 4.9.2)
///
/// The replace_sm_resp PDU is used to return the result of a replace_sm request.
/// This PDU contains no mandatory parameters beyond the standard PDU header.
///
/// ## References
/// - SMPP v3.4 Specification Section 4.9.2
#[derive(Clone, Debug, PartialEq)]
pub struct ReplaceSmResponse {
    pub command_status: CommandStatus,
    pub sequence_number: u32,
    // No additional mandatory parameters
}

impl ReplaceSmResponse {
    /// Create a new ReplaceSmResponse PDU
    pub fn new(
        sequence_number: u32,
        command_status: CommandStatus,
    ) -> Result<Self, ReplaceSmResponseValidationError> {
        let pdu = ReplaceSmResponse {
            command_status,
            sequence_number,
        };

        // Validate the PDU
        pdu.validate()?;
        Ok(pdu)
    }

    /// Create a successful ReplaceSmResponse
    pub fn success(sequence_number: u32) -> Self {
        ReplaceSmResponse {
            command_status: CommandStatus::Ok,
            sequence_number,
        }
    }

    /// Create an error ReplaceSmResponse
    pub fn error(sequence_number: u32, command_status: CommandStatus) -> Self {
        ReplaceSmResponse {
            command_status,
            sequence_number,
        }
    }

    /// Validate the ReplaceSmResponse PDU
    fn validate(&self) -> Result<(), ReplaceSmResponseValidationError> {
        // No additional validation needed
        Ok(())
    }
}

impl Encodable for ReplaceSmResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // PDU Header (will be filled by codec)
        buf.put_u32(0); // command_length (placeholder)
        buf.put_u32(CommandId::ReplaceSmResp as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // No additional mandatory parameters
        Ok(())
    }
}

impl Decodable for ReplaceSmResponse {
    fn decode(header: PduHeader, _buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // No additional parameters to decode
        Ok(ReplaceSmResponse {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
        })
    }

    fn command_id() -> CommandId {
        CommandId::ReplaceSmResp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datatypes::{NumericPlanIndicator, TypeOfNumber};

    #[test]
    fn test_replace_sm_creation() {
        let message_id = MessageId::new(b"12345678").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let short_message = ShortMessage::new(b"Hello replacement").unwrap();

        let replace_sm = ReplaceSm::new(
            123,
            message_id,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            ScheduleDeliveryTime::new("").unwrap(),
            ValidityPeriod::new("").unwrap(),
            0x01, // registered_delivery
            0x00, // sm_default_msg_id
            short_message,
        )
        .unwrap();

        assert_eq!(replace_sm.sequence_number, 123);
        assert_eq!(replace_sm.command_status, CommandStatus::Ok);
        assert_eq!(replace_sm.message_id.as_str().unwrap(), "12345678");
        assert_eq!(replace_sm.source_addr_ton, TypeOfNumber::International);
        assert_eq!(replace_sm.source_addr_npi, NumericPlanIndicator::Isdn);
        assert_eq!(replace_sm.source_addr.as_str().unwrap(), "1234567890");
        assert_eq!(replace_sm.registered_delivery, 0x01);
        assert_eq!(replace_sm.sm_default_msg_id, 0x00);
        assert_eq!(replace_sm.sm_length, 17); // "Hello replacement" length
        assert_eq!(
            replace_sm.short_message.as_str().unwrap(),
            "Hello replacement"
        );
    }

    #[test]
    fn test_replace_sm_encoding_decoding() {
        let message_id = MessageId::new(b"MSG001").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let short_message = ShortMessage::new(b"New message").unwrap();

        let original = ReplaceSm::new(
            456,
            message_id,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            ScheduleDeliveryTime::new("").unwrap(),
            ValidityPeriod::new("").unwrap(),
            0x01,
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
            command_id: CommandId::ReplaceSm,
            command_status: CommandStatus::Ok,
            sequence_number: 456,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = ReplaceSm::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_replace_sm_response_creation() {
        let response = ReplaceSmResponse::new(789, CommandStatus::Ok).unwrap();

        assert_eq!(response.sequence_number, 789);
        assert_eq!(response.command_status, CommandStatus::Ok);
    }

    #[test]
    fn test_replace_sm_response_success() {
        let response = ReplaceSmResponse::success(456);

        assert_eq!(response.sequence_number, 456);
        assert_eq!(response.command_status, CommandStatus::Ok);
    }

    #[test]
    fn test_replace_sm_response_error() {
        let response = ReplaceSmResponse::error(789, CommandStatus::InvalidSourceAddress);

        assert_eq!(response.sequence_number, 789);
        assert_eq!(response.command_status, CommandStatus::InvalidSourceAddress);
    }

    #[test]
    fn test_replace_sm_response_encoding_decoding() {
        let original = ReplaceSmResponse::success(999);

        // Test encoding
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Test decoding
        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::ReplaceSmResp,
            command_status: CommandStatus::Ok,
            sequence_number: 999,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = ReplaceSmResponse::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_replace_sm_with_scheduled_delivery() {
        let message_id = MessageId::new(b"MSG003").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let short_message = ShortMessage::new(b"Scheduled").unwrap();

        let replace_sm = ReplaceSm::new(
            111,
            message_id,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            ScheduleDeliveryTime::new("240101120000000R").unwrap(), // Scheduled time
            ValidityPeriod::new("240101180000000R").unwrap(),       // Validity period
            0x01,
            0x00,
            short_message,
        )
        .unwrap();

        assert_eq!(
            replace_sm.schedule_delivery_time.as_str().unwrap(),
            "240101120000000R"
        );
        assert_eq!(
            replace_sm.validity_period.as_str().unwrap(),
            "240101180000000R"
        );

        // Test encoding/decoding with scheduled delivery
        let mut buf = BytesMut::new();
        replace_sm.encode(&mut buf).unwrap();

        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::ReplaceSm,
            command_status: CommandStatus::Ok,
            sequence_number: 111,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = ReplaceSm::decode(header, &mut cursor).unwrap();

        assert_eq!(replace_sm, decoded);
    }
}
