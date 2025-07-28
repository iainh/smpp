// ABOUTME: SMPP v5.0 query_broadcast_sm PDU implementation for broadcast message status queries
// ABOUTME: Provides broadcast message status query functionality per SMPP v5.0 specification

use crate::codec::{CodecError, Decodable, Encodable};
use crate::datatypes::{
    CommandId, CommandStatus, MessageId, TypeOfNumber, NumericPlanIndicator, MessageState,
    FixedStringError, SmppDateTime
};
use crate::codec::{encode_cstring, encode_u8, decode_cstring, decode_u8};
use bytes::{BufMut, BytesMut};
use std::io::Cursor;
use thiserror::Error;

/// Validation errors for QueryBroadcastSm PDU
#[derive(Debug, Error)]
pub enum QueryBroadcastSmValidationError {
    #[error("Message ID error: {0}")]
    MessageId(#[from] FixedStringError),
    #[error("Message ID cannot be empty")]
    EmptyMessageId,
}

/// SMPP v5.0 query_broadcast_sm PDU for querying broadcast message status
///
/// The query_broadcast_sm operation is used by an ESME to query the state of a previously 
/// submitted broadcast message. The matching algorithm used to find messages submitted by 
/// query_broadcast_sm is a match of the source_addr and message_id fields.
///
/// ## Mandatory Parameters
/// - message_id: Message ID of the broadcast message whose state is to be queried
/// - source_addr_ton: Type of Number of message originator  
/// - source_addr_npi: Numbering Plan Indicator of message originator
/// - source_addr: Address of message originator
#[derive(Clone, Debug, PartialEq)]
pub struct QueryBroadcastSm {
    pub command_status: CommandStatus,
    pub sequence_number: u32,
    pub message_id: MessageId,
    pub source_addr_ton: TypeOfNumber,
    pub source_addr_npi: NumericPlanIndicator,
    pub source_addr: String,
}

/// SMPP v5.0 query_broadcast_sm_resp PDU
#[derive(Clone, Debug, PartialEq)]
pub struct QueryBroadcastSmResponse {
    pub command_status: CommandStatus,
    pub sequence_number: u32,
    pub message_id: MessageId,
    pub message_state: MessageState,
    pub final_date: Option<SmppDateTime>,
}

impl QueryBroadcastSm {
    /// Create a builder for QueryBroadcastSm
    pub fn builder() -> QueryBroadcastSmBuilder {
        QueryBroadcastSmBuilder::default()
    }

    /// Get the sequence number
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// Get the message ID
    pub fn message_id(&self) -> &str {
        self.message_id.as_str().unwrap_or("")
    }

    /// Get the source address TON
    pub fn source_addr_ton(&self) -> TypeOfNumber {
        self.source_addr_ton
    }

    /// Get the source address NPI
    pub fn source_addr_npi(&self) -> NumericPlanIndicator {
        self.source_addr_npi
    }

    /// Get the source address
    pub fn source_addr(&self) -> &str {
        &self.source_addr
    }
}

impl QueryBroadcastSmResponse {
    /// Create a new QueryBroadcastSmResponse
    pub fn new(
        sequence_number: u32, 
        command_status: CommandStatus, 
        message_id: &str,
        message_state: MessageState,
        final_date: Option<SmppDateTime>
    ) -> Self {
        Self {
            command_status,
            sequence_number,
            message_id: MessageId::from(message_id),
            message_state,
            final_date,
        }
    }

    /// Get the sequence number
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// Get the command status
    pub fn command_status(&self) -> CommandStatus {
        self.command_status
    }

    /// Get the message ID
    pub fn message_id(&self) -> &str {
        self.message_id.as_str().unwrap_or("")
    }

    /// Get the message state
    pub fn message_state(&self) -> MessageState {
        self.message_state.clone()
    }

    /// Get the final date
    pub fn final_date(&self) -> Option<&SmppDateTime> {
        self.final_date.as_ref()
    }
}

/// Builder for QueryBroadcastSm PDU
#[derive(Default)]
pub struct QueryBroadcastSmBuilder {
    sequence_number: Option<u32>,
    message_id: Option<String>,
    source_addr_ton: Option<TypeOfNumber>,
    source_addr_npi: Option<NumericPlanIndicator>,
    source_addr: Option<String>,
}

impl QueryBroadcastSmBuilder {
    pub fn sequence_number(mut self, sequence_number: u32) -> Self {
        self.sequence_number = Some(sequence_number);
        self
    }

    pub fn message_id(mut self, message_id: &str) -> Self {
        self.message_id = Some(message_id.to_string());
        self
    }

    pub fn source_addr(mut self, addr: &str, ton: TypeOfNumber, npi: NumericPlanIndicator) -> Self {
        self.source_addr = Some(addr.to_string());
        self.source_addr_ton = Some(ton);
        self.source_addr_npi = Some(npi);
        self
    }

    pub fn build(self) -> Result<QueryBroadcastSm, QueryBroadcastSmValidationError> {
        let message_id_str = self.message_id.unwrap_or_default();
        if message_id_str.is_empty() {
            return Err(QueryBroadcastSmValidationError::EmptyMessageId);
        }

        Ok(QueryBroadcastSm {
            command_status: CommandStatus::Ok,
            sequence_number: self.sequence_number.unwrap_or(1),
            message_id: MessageId::from(message_id_str.as_str()),
            source_addr_ton: self.source_addr_ton.unwrap_or(TypeOfNumber::Unknown),
            source_addr_npi: self.source_addr_npi.unwrap_or(NumericPlanIndicator::Unknown),
            source_addr: self.source_addr.unwrap_or_default(),
        })
    }
}

impl Decodable for QueryBroadcastSm {
    fn decode(header: crate::codec::PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory parameters according to SMPP v5.0 query_broadcast_sm specification
        
        // message_id (65 octets, null-terminated with padding)
        let message_id_str = decode_cstring(buf, 65, "message_id")?;
        let message_id = MessageId::from(message_id_str.as_str());

        // source_addr_ton (1 octet)
        let source_addr_ton = TypeOfNumber::try_from(decode_u8(buf)?)
            .map_err(|_| CodecError::FieldValidation {
                field: "source_addr_ton",
                reason: "Invalid type of number".to_string(),
            })?;

        // source_addr_npi (1 octet)
        let source_addr_npi = NumericPlanIndicator::try_from(decode_u8(buf)?)
            .map_err(|_| CodecError::FieldValidation {
                field: "source_addr_npi",
                reason: "Invalid numeric plan indicator".to_string(),
            })?;

        // source_addr (21 octets, null-terminated with padding)
        let source_addr = decode_cstring(buf, 21, "source_addr")?;

        Ok(QueryBroadcastSm {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            message_id,
            source_addr_ton,
            source_addr_npi,
            source_addr,
        })
    }

    fn command_id() -> CommandId {
        CommandId::QueryBroadcastSm
    }
}

impl Encodable for QueryBroadcastSm {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Encode PDU header
        buf.put_u32(0); // command_length (will be set by to_bytes)
        buf.put_u32(Self::command_id() as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Encode mandatory parameters according to SMPP v5.0 query_broadcast_sm specification
        
        // message_id (65 octets, null-terminated with padding)
        encode_cstring(buf, self.message_id.as_str().unwrap_or(""), 65);

        // source_addr_ton (1 octet)
        encode_u8(buf, self.source_addr_ton as u8);

        // source_addr_npi (1 octet)
        encode_u8(buf, self.source_addr_npi as u8);

        // source_addr (21 octets, null-terminated with padding)
        encode_cstring(buf, &self.source_addr, 21);

        Ok(())
    }
}

impl Decodable for QueryBroadcastSmResponse {
    fn decode(header: crate::codec::PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory parameters according to SMPP v5.0 query_broadcast_sm_resp specification
        
        // message_id (65 octets, null-terminated with padding)
        let message_id_str = decode_cstring(buf, 65, "message_id")?;
        let message_id = MessageId::from(message_id_str.as_str());

        // message_state (1 octet)
        let message_state = MessageState::try_from(decode_u8(buf)?)
            .map_err(|_| CodecError::FieldValidation {
                field: "message_state",
                reason: "Invalid message state".to_string(),
            })?;

        // final_date (17 octets, null-terminated with padding)
        let final_date_str = decode_cstring(buf, 17, "final_date")?;
        let final_date = if final_date_str.is_empty() {
            None
        } else {
            Some(SmppDateTime::from(final_date_str.as_str()))
        };

        Ok(QueryBroadcastSmResponse {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            message_id,
            message_state,
            final_date,
        })
    }

    fn command_id() -> CommandId {
        CommandId::QueryBroadcastSmResp
    }
}

impl Encodable for QueryBroadcastSmResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Encode PDU header
        buf.put_u32(0); // command_length (will be set by to_bytes)
        buf.put_u32(Self::command_id() as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Encode mandatory parameters according to SMPP v5.0 query_broadcast_sm_resp specification
        
        // message_id (65 octets, null-terminated with padding)
        encode_cstring(buf, self.message_id.as_str().unwrap_or(""), 65);

        // message_state (1 octet)
        encode_u8(buf, self.message_state.clone() as u8);

        // final_date (17 octets, null-terminated with padding)
        let final_date_str = self.final_date
            .as_ref()
            .map(|dt| dt.as_str().unwrap_or(""))
            .unwrap_or("");
        encode_cstring(buf, final_date_str, 17);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_broadcast_sm_builder() {
        let result = QueryBroadcastSm::builder()
            .sequence_number(42)
            .message_id("BC001")
            .source_addr("1234567890", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .build();

        assert!(result.is_ok());
        let pdu = result.unwrap();
        assert_eq!(pdu.sequence_number(), 42);
        assert_eq!(pdu.message_id(), "BC001");
        assert_eq!(pdu.source_addr(), "1234567890");
    }

    #[test]
    fn test_query_broadcast_sm_validation() {
        // Test empty message_id
        let result = QueryBroadcastSm::builder()
            .message_id("")
            .source_addr("1234567890", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_query_broadcast_sm_response() {
        let response = QueryBroadcastSmResponse::new(
            42, 
            CommandStatus::Ok, 
            "BC001",
            MessageState::Delivered,
            None
        );
        assert_eq!(response.sequence_number(), 42);
        assert_eq!(response.command_status(), CommandStatus::Ok);
        assert_eq!(response.message_id(), "BC001");
        assert_eq!(response.message_state(), MessageState::Delivered);
    }
}