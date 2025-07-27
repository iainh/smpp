// ABOUTME: Implements SMPP v3.4 query_sm and query_sm_resp PDUs for message status queries
// ABOUTME: Provides status query functionality per specification Section 4.8

use crate::datatypes::{
    AddressError, CommandId, CommandStatus, FixedStringError, MessageId, NumericPlanIndicator,
    SourceAddr, TypeOfNumber,
};
use bytes::{BufMut, BytesMut};
use std::io::Cursor;
use thiserror::Error;

// Import codec traits
use crate::codec::{
    CodecError, Decodable, Encodable, PduHeader, decode_cstring, decode_u8, encode_cstring,
    encode_u8,
};

/// Validation errors for QuerySm PDU
#[derive(Debug, Error)]
pub enum QuerySmValidationError {
    #[error("Message ID error: {0}")]
    MessageId(#[from] FixedStringError),
    #[error("Source address error: {0}")]
    SourceAddr(#[from] AddressError),
}

/// SMPP v3.4 query_sm PDU (Section 4.8.1)
///
/// The query_sm operation is used by an ESME to query the state of a previously submitted short message.
/// The matching algorithm used to find messages submitted by query_sm is a match of the source_addr and message_id fields.
/// Where the original submit_sm 'source_addr' was defaulted to NULL, then the source_addr in the query_sm should also be NULL.
///
/// ## Mandatory Parameters
/// - message_id: Message ID of the message whose state is to be queried
/// - source_addr_ton: Type of Number of message originator  
/// - source_addr_npi: Numbering Plan Indicator of message originator
/// - source_addr: Address of message originator
///
/// ## References
/// - SMPP v3.4 Specification Section 4.8.1
#[derive(Clone, Debug, PartialEq)]
pub struct QuerySm {
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Mandatory parameters
    /// Message ID of the message whose state is to be queried.
    /// This should match the message_id returned in the submit_sm_resp PDU.
    pub message_id: MessageId,

    /// Type of Number of message originator.
    /// Should match the source_addr_ton used in the original submit_sm.
    pub source_addr_ton: TypeOfNumber,

    /// Numbering Plan Indicator of message originator.
    /// Should match the source_addr_npi used in the original submit_sm.
    pub source_addr_npi: NumericPlanIndicator,

    /// Address of message originator.
    /// Should match the source_addr used in the original submit_sm.
    /// If original submit_sm had NULL source_addr, this should also be NULL.
    pub source_addr: SourceAddr,
}

impl QuerySm {
    /// Create a new QuerySm PDU
    pub fn new(
        sequence_number: u32,
        message_id: MessageId,
        source_addr_ton: TypeOfNumber,
        source_addr_npi: NumericPlanIndicator,
        source_addr: SourceAddr,
    ) -> Result<Self, QuerySmValidationError> {
        let pdu = QuerySm {
            command_status: CommandStatus::Ok, // Always 0 for requests
            sequence_number,
            message_id,
            source_addr_ton,
            source_addr_npi,
            source_addr,
        };

        // Validate the PDU
        pdu.validate()?;
        Ok(pdu)
    }

    /// Validate the QuerySm PDU
    fn validate(&self) -> Result<(), QuerySmValidationError> {
        // message_id validation is handled by MessageId type
        // source_addr validation is handled by SourceAddr type
        Ok(())
    }
}

impl Encodable for QuerySm {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // PDU Header (will be filled by codec)
        buf.put_u32(0); // command_length (placeholder)
        buf.put_u32(CommandId::QuerySm as u32);
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

        Ok(())
    }
}

impl Decodable for QuerySm {
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

        Ok(QuerySm {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            message_id,
            source_addr_ton,
            source_addr_npi,
            source_addr,
        })
    }

    fn command_id() -> CommandId {
        CommandId::QuerySm
    }
}

/// Message state values for query_sm_resp PDU
/// Per SMPP v3.4 specification Section 4.8.2, Table 4-20
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageState {
    /// The message is in enroute state
    Enroute = 0x01,
    /// Message is delivered to destination
    Delivered = 0x02,
    /// Message expired before delivery
    Expired = 0x03,
    /// Message has been deleted
    Deleted = 0x04,
    /// Message is in invalid state
    Undeliverable = 0x05,
    /// Message is in accepted state
    Accepted = 0x06,
    /// Message validity period has expired
    Unknown = 0x07,
    /// Message is in invalid state
    Rejected = 0x08,
}

impl TryFrom<u8> for MessageState {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MessageState::Enroute),
            0x02 => Ok(MessageState::Delivered),
            0x03 => Ok(MessageState::Expired),
            0x04 => Ok(MessageState::Deleted),
            0x05 => Ok(MessageState::Undeliverable),
            0x06 => Ok(MessageState::Accepted),
            0x07 => Ok(MessageState::Unknown),
            0x08 => Ok(MessageState::Rejected),
            _ => Err(()),
        }
    }
}

/// Validation errors for QuerySmResponse PDU
#[derive(Debug, Error)]
pub enum QuerySmResponseValidationError {
    #[error("Message ID error: {0}")]
    MessageId(#[from] FixedStringError),
}

/// SMPP v3.4 query_sm_resp PDU (Section 4.8.2)
///
/// The query_sm_resp PDU is used to return the status of a queried short message.
///
/// ## Mandatory Parameters
/// - message_id: Message ID of the queried message
/// - final_date: Date and time when the queried message reached a final state
/// - message_state: Current state of the queried message
/// - error_code: Network error code associated with the message state
///
/// ## References
/// - SMPP v3.4 Specification Section 4.8.2
#[derive(Clone, Debug, PartialEq)]
pub struct QuerySmResponse {
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Mandatory parameters
    /// Message ID of the queried message (matches original query_sm)
    pub message_id: MessageId,

    /// Date and time when the queried message reached a final state.
    /// Format: YYMMDDhhmm where YY = last two digits of year,
    /// MM = month (01-12), DD = day (01-31), hh = hour (00-23), mm = minute (00-59).
    /// Set to NULL if message has not yet reached a final state.
    pub final_date: Option<String>, // Using String for now, could be replaced with a proper DateTime type

    /// Current state of the queried message
    pub message_state: MessageState,

    /// Network error code associated with the message state.
    /// The actual error code returned depends on the underlying network.
    pub error_code: u8,
}

impl QuerySmResponse {
    /// Create a new QuerySmResponse PDU
    pub fn new(
        sequence_number: u32,
        command_status: CommandStatus,
        message_id: MessageId,
        final_date: Option<String>,
        message_state: MessageState,
        error_code: u8,
    ) -> Result<Self, QuerySmResponseValidationError> {
        let pdu = QuerySmResponse {
            command_status,
            sequence_number,
            message_id,
            final_date,
            message_state,
            error_code,
        };

        // Validate the PDU
        pdu.validate()?;
        Ok(pdu)
    }

    /// Validate the QuerySmResponse PDU
    fn validate(&self) -> Result<(), QuerySmResponseValidationError> {
        // message_id validation is handled by MessageId type
        // final_date should be validated for format, but using simple String for now
        Ok(())
    }
}

impl Encodable for QuerySmResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // PDU Header (will be filled by codec)
        buf.put_u32(0); // command_length (placeholder)
        buf.put_u32(CommandId::QuerySmResp as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Mandatory parameters
        // message_id (65 octets, null-terminated with padding)
        encode_cstring(buf, self.message_id.as_str().unwrap_or(""), 65);

        // final_date (17 octets, null-terminated, format: YYMMDDhhmm0000)
        let final_date_str = self.final_date.as_deref().unwrap_or("");
        encode_cstring(buf, final_date_str, 17);

        // message_state (1 octet)
        encode_u8(buf, self.message_state.clone() as u8);

        // error_code (1 octet)
        encode_u8(buf, self.error_code);

        Ok(())
    }
}

impl Decodable for QuerySmResponse {
    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory parameters
        let message_id_str = decode_cstring(buf, 65, "message_id")?;
        let message_id =
            MessageId::new(message_id_str.as_bytes()).map_err(|e| CodecError::FieldValidation {
                field: "message_id",
                reason: format!("{e}"),
            })?;

        let final_date_str = decode_cstring(buf, 17, "final_date")?;
        let final_date = if final_date_str.is_empty() {
            None
        } else {
            Some(final_date_str)
        };

        let message_state =
            MessageState::try_from(decode_u8(buf)?).map_err(|_| CodecError::FieldValidation {
                field: "message_state",
                reason: "Invalid MessageState value".to_string(),
            })?;

        let error_code = decode_u8(buf)?;

        Ok(QuerySmResponse {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            message_id,
            final_date,
            message_state,
            error_code,
        })
    }

    fn command_id() -> CommandId {
        CommandId::QuerySmResp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datatypes::{NumericPlanIndicator, TypeOfNumber};

    #[test]
    fn test_query_sm_creation() {
        let message_id = MessageId::new(b"12345678").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();

        let query_sm = QuerySm::new(
            123,
            message_id,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
        )
        .unwrap();

        assert_eq!(query_sm.sequence_number, 123);
        assert_eq!(query_sm.command_status, CommandStatus::Ok);
        assert_eq!(query_sm.message_id.as_str().unwrap(), "12345678");
        assert_eq!(query_sm.source_addr_ton, TypeOfNumber::International);
        assert_eq!(query_sm.source_addr_npi, NumericPlanIndicator::Isdn);
        assert_eq!(query_sm.source_addr.as_str().unwrap(), "1234567890");
    }

    #[test]
    fn test_query_sm_encoding_decoding() {
        let message_id = MessageId::new(b"MSG001").unwrap();
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();

        let original = QuerySm::new(
            456,
            message_id,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
        )
        .unwrap();

        // Test encoding
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Test decoding
        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::QuerySm,
            command_status: CommandStatus::Ok,
            sequence_number: 456,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = QuerySm::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_query_sm_response_creation() {
        let message_id = MessageId::new(b"MSG001").unwrap();

        let response = QuerySmResponse::new(
            789,
            CommandStatus::Ok,
            message_id,
            Some("2401011200".to_string()),
            MessageState::Delivered,
            0,
        )
        .unwrap();

        assert_eq!(response.sequence_number, 789);
        assert_eq!(response.command_status, CommandStatus::Ok);
        assert_eq!(response.message_id.as_str().unwrap(), "MSG001");
        assert_eq!(response.final_date, Some("2401011200".to_string()));
        assert_eq!(response.message_state, MessageState::Delivered);
        assert_eq!(response.error_code, 0);
    }

    #[test]
    fn test_query_sm_response_encoding_decoding() {
        let message_id = MessageId::new(b"MSG002").unwrap();

        let original = QuerySmResponse::new(
            999,
            CommandStatus::Ok,
            message_id,
            Some("2401011200".to_string()),
            MessageState::Delivered,
            0,
        )
        .unwrap();

        // Test encoding
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Test decoding
        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::QuerySmResp,
            command_status: CommandStatus::Ok,
            sequence_number: 999,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = QuerySmResponse::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_message_state_conversion() {
        assert_eq!(MessageState::try_from(0x01).unwrap(), MessageState::Enroute);
        assert_eq!(
            MessageState::try_from(0x02).unwrap(),
            MessageState::Delivered
        );
        assert_eq!(MessageState::try_from(0x03).unwrap(), MessageState::Expired);
        assert_eq!(MessageState::try_from(0x04).unwrap(), MessageState::Deleted);
        assert_eq!(
            MessageState::try_from(0x05).unwrap(),
            MessageState::Undeliverable
        );
        assert_eq!(
            MessageState::try_from(0x06).unwrap(),
            MessageState::Accepted
        );
        assert_eq!(MessageState::try_from(0x07).unwrap(), MessageState::Unknown);
        assert_eq!(
            MessageState::try_from(0x08).unwrap(),
            MessageState::Rejected
        );

        // Test invalid state
        assert!(MessageState::try_from(0xFF).is_err());
    }

    #[test]
    fn test_query_sm_response_null_final_date() {
        let message_id = MessageId::new(b"MSG003").unwrap();

        let response = QuerySmResponse::new(
            111,
            CommandStatus::Ok,
            message_id,
            None, // NULL final_date
            MessageState::Enroute,
            0,
        )
        .unwrap();

        assert_eq!(response.final_date, None);

        // Test encoding/decoding with NULL final_date
        let mut buf = BytesMut::new();
        response.encode(&mut buf).unwrap();

        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::QuerySmResp,
            command_status: CommandStatus::Ok,
            sequence_number: 111,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = QuerySmResponse::decode(header, &mut cursor).unwrap();

        assert_eq!(response, decoded);
        assert_eq!(decoded.final_date, None);
    }
}
