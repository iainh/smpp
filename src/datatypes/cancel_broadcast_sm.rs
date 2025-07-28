// ABOUTME: SMPP v5.0 cancel_broadcast_sm PDU implementation for broadcast message cancellation
// ABOUTME: Provides broadcast message cancellation functionality per SMPP v5.0 specification

use crate::codec::{CodecError, Decodable, Encodable};
use crate::datatypes::{
    CommandId, CommandStatus, ServiceType, MessageId, TypeOfNumber, NumericPlanIndicator,
    FixedStringError, ServiceTypeError
};
use crate::codec::{encode_cstring, encode_u8, decode_cstring, decode_u8};
use bytes::{BufMut, BytesMut};
use std::io::Cursor;
use thiserror::Error;

/// Validation errors for CancelBroadcastSm PDU
#[derive(Debug, Error)]
pub enum CancelBroadcastSmValidationError {
    #[error("Service type error: {0}")]
    ServiceType(#[from] ServiceTypeError),
    #[error("Message ID error: {0}")]
    MessageId(#[from] FixedStringError),
    #[error("Message ID cannot be empty")]
    EmptyMessageId,
}

/// SMPP v5.0 cancel_broadcast_sm PDU for cancelling broadcast messages
///
/// The cancel_broadcast_sm operation is used by an ESME to cancel a previously submitted 
/// broadcast message that is still pending delivery. The matching algorithm used to find 
/// the message to cancel is implementation specific, but must include matching of the 
/// source address and message_id.
///
/// ## Mandatory Parameters
/// - service_type: The service_type parameter can be used to indicate the SMS Application service
/// - message_id: Message ID of the broadcast message to be cancelled
/// - source_addr_ton: Type of Number of message originator  
/// - source_addr_npi: Numbering Plan Indicator of message originator
/// - source_addr: Address of message originator
#[derive(Clone, Debug, PartialEq)]
pub struct CancelBroadcastSm {
    pub command_status: CommandStatus,
    pub sequence_number: u32,
    pub service_type: ServiceType,
    pub message_id: MessageId,
    pub source_addr_ton: TypeOfNumber,
    pub source_addr_npi: NumericPlanIndicator,
    pub source_addr: String,
}

/// SMPP v5.0 cancel_broadcast_sm_resp PDU
#[derive(Clone, Debug, PartialEq)]
pub struct CancelBroadcastSmResponse {
    pub command_status: CommandStatus,
    pub sequence_number: u32,
}

impl CancelBroadcastSm {
    /// Create a builder for CancelBroadcastSm
    pub fn builder() -> CancelBroadcastSmBuilder {
        CancelBroadcastSmBuilder::default()
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

    /// Get the service type
    pub fn service_type(&self) -> &ServiceType {
        &self.service_type
    }
}

impl CancelBroadcastSmResponse {
    /// Create a new CancelBroadcastSmResponse
    pub fn new(sequence_number: u32, command_status: CommandStatus) -> Self {
        Self {
            command_status,
            sequence_number,
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
}

/// Builder for CancelBroadcastSm PDU
#[derive(Default)]
pub struct CancelBroadcastSmBuilder {
    sequence_number: Option<u32>,
    service_type: Option<ServiceType>,
    message_id: Option<String>,
    source_addr_ton: Option<TypeOfNumber>,
    source_addr_npi: Option<NumericPlanIndicator>,
    source_addr: Option<String>,
}

impl CancelBroadcastSmBuilder {
    pub fn sequence_number(mut self, sequence_number: u32) -> Self {
        self.sequence_number = Some(sequence_number);
        self
    }

    pub fn service_type(mut self, service_type: ServiceType) -> Self {
        self.service_type = Some(service_type);
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

    pub fn build(self) -> Result<CancelBroadcastSm, CancelBroadcastSmValidationError> {
        let message_id_str = self.message_id.unwrap_or_default();
        if message_id_str.is_empty() {
            return Err(CancelBroadcastSmValidationError::EmptyMessageId);
        }

        Ok(CancelBroadcastSm {
            command_status: CommandStatus::Ok,
            sequence_number: self.sequence_number.unwrap_or(1),
            service_type: self.service_type.unwrap_or_default(),
            message_id: MessageId::from(message_id_str.as_str()),
            source_addr_ton: self.source_addr_ton.unwrap_or(TypeOfNumber::Unknown),
            source_addr_npi: self.source_addr_npi.unwrap_or(NumericPlanIndicator::Unknown),
            source_addr: self.source_addr.unwrap_or_default(),
        })
    }
}

impl Decodable for CancelBroadcastSm {
    fn decode(header: crate::codec::PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory parameters according to SMPP v5.0 cancel_broadcast_sm specification
        
        // service_type (6 octets, null-terminated with padding)
        let service_type_str = decode_cstring(buf, 6, "service_type")?;
        let service_type = ServiceType::from(service_type_str.as_str());

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

        Ok(CancelBroadcastSm {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            service_type,
            message_id,
            source_addr_ton,
            source_addr_npi,
            source_addr,
        })
    }

    fn command_id() -> CommandId {
        CommandId::CancelBroadcastSm
    }
}

impl Encodable for CancelBroadcastSm {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Encode PDU header
        buf.put_u32(0); // command_length (will be set by to_bytes)
        buf.put_u32(Self::command_id() as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Encode mandatory parameters according to SMPP v5.0 cancel_broadcast_sm specification
        
        // service_type (6 octets, null-terminated with padding)
        encode_cstring(buf, &self.service_type.to_string(), 6);

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

impl Decodable for CancelBroadcastSmResponse {
    fn decode(header: crate::codec::PduHeader, _buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // cancel_broadcast_sm_resp has no body, only the PDU header
        Ok(CancelBroadcastSmResponse {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
        })
    }

    fn command_id() -> CommandId {
        CommandId::CancelBroadcastSmResp
    }
}

impl Encodable for CancelBroadcastSmResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Encode PDU header
        buf.put_u32(0); // command_length (will be set by to_bytes)
        buf.put_u32(Self::command_id() as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // cancel_broadcast_sm_resp has no body, only the PDU header
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cancel_broadcast_sm_builder() {
        let result = CancelBroadcastSm::builder()
            .sequence_number(55)
            .service_type(ServiceType::default())
            .message_id("BC001")
            .source_addr("1234567890", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .build();

        assert!(result.is_ok());
        let pdu = result.unwrap();
        assert_eq!(pdu.sequence_number(), 55);
        assert_eq!(pdu.message_id(), "BC001");
        assert_eq!(pdu.source_addr(), "1234567890");
    }

    #[test]
    fn test_cancel_broadcast_sm_validation() {
        // Test empty message_id
        let result = CancelBroadcastSm::builder()
            .service_type(ServiceType::default())
            .message_id("")
            .source_addr("1234567890", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_cancel_broadcast_sm_response() {
        let response = CancelBroadcastSmResponse::new(55, CommandStatus::Ok);
        assert_eq!(response.sequence_number(), 55);
        assert_eq!(response.command_status(), CommandStatus::Ok);
    }
}