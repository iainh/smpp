// ABOUTME: SMPP v5.0 broadcast_sm PDU implementation for broadcast messaging
// ABOUTME: Handles broadcast message submission with area identification and scheduling

use crate::codec::{CodecError, Decodable, Encodable};
use crate::datatypes::{
    CommandId, CommandStatus, ServiceType, DataCoding, PriorityFlag, 
    ScheduleDeliveryTime, ValidityPeriod, MessageId, TypeOfNumber, NumericPlanIndicator
};
use crate::codec::{encode_cstring, encode_u8, encode_u16, encode_u32, decode_cstring, decode_u8, decode_u16, decode_u32};
use bytes::{Buf, BufMut, BytesMut};
use std::io::Cursor;

/// SMPP v5.0 broadcast_sm PDU for sending broadcast messages
#[derive(Clone, Debug, PartialEq)]
pub struct BroadcastSm {
    pub command_status: CommandStatus,
    pub sequence_number: u32,
    pub service_type: ServiceType,
    pub source_addr_ton: TypeOfNumber,
    pub source_addr_npi: NumericPlanIndicator,
    pub source_addr: String,
    pub message_id: MessageId,
    pub priority_flag: PriorityFlag,
    pub schedule_delivery_time: ScheduleDeliveryTime,
    pub validity_period: ValidityPeriod,
    pub data_coding: DataCoding,
    pub broadcast_area_identifier: Vec<u8>,
    pub broadcast_content_type: u8,
    pub broadcast_rep_num: u16,
    pub broadcast_frequency_interval: u32,
}

/// SMPP v5.0 broadcast_sm_resp PDU
#[derive(Clone, Debug, PartialEq)]
pub struct BroadcastSmResponse {
    pub command_status: CommandStatus,
    pub sequence_number: u32,
    pub message_id: MessageId,
}

/// Validation error for BroadcastSm PDU
#[derive(Debug, thiserror::Error)]
pub enum BroadcastSmValidationError {
    #[error("broadcast_area_identifier cannot be empty")]
    EmptyBroadcastAreaIdentifier,
    #[error("broadcast_rep_num must be greater than 0")]
    InvalidBroadcastRepNum,
    #[error("message_id too long (max 64 characters)")]
    MessageIdTooLong,
}

impl BroadcastSm {
    /// Create a builder for BroadcastSm
    pub fn builder() -> BroadcastSmBuilder {
        BroadcastSmBuilder::default()
    }

    /// Get the sequence number
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// Get the message ID
    pub fn message_id(&self) -> &str {
        self.message_id.as_str().unwrap_or("")
    }

    /// Get the broadcast repetition number
    pub fn broadcast_rep_num(&self) -> u16 {
        self.broadcast_rep_num
    }

    /// Get the broadcast frequency interval
    pub fn broadcast_frequency_interval(&self) -> u32 {
        self.broadcast_frequency_interval
    }
}

impl BroadcastSmResponse {
    /// Create a new BroadcastSmResponse
    pub fn new(sequence_number: u32, command_status: CommandStatus, message_id: &str) -> Self {
        Self {
            command_status,
            sequence_number,
            message_id: MessageId::from(message_id),
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
}

/// Builder for BroadcastSm PDU
#[derive(Default)]
pub struct BroadcastSmBuilder {
    sequence_number: Option<u32>,
    service_type: Option<ServiceType>,
    source_addr_ton: Option<TypeOfNumber>,
    source_addr_npi: Option<NumericPlanIndicator>,
    source_addr: Option<String>,
    message_id: Option<String>,
    priority_flag: Option<PriorityFlag>,
    schedule_delivery_time: Option<ScheduleDeliveryTime>,
    validity_period: Option<ValidityPeriod>,
    data_coding: Option<DataCoding>,
    broadcast_area_identifier: Option<Vec<u8>>,
    broadcast_content_type: Option<u8>,
    broadcast_rep_num: Option<u16>,
    broadcast_frequency_interval: Option<u32>,
}

impl BroadcastSmBuilder {
    pub fn sequence_number(mut self, sequence_number: u32) -> Self {
        self.sequence_number = Some(sequence_number);
        self
    }

    pub fn service_type(mut self, service_type: ServiceType) -> Self {
        self.service_type = Some(service_type);
        self
    }

    pub fn source_addr(mut self, addr: &str, ton: TypeOfNumber, npi: NumericPlanIndicator) -> Self {
        self.source_addr = Some(addr.to_string());
        self.source_addr_ton = Some(ton);
        self.source_addr_npi = Some(npi);
        self
    }

    pub fn message_id(mut self, message_id: &str) -> Self {
        self.message_id = Some(message_id.to_string());
        self
    }

    pub fn priority_flag(mut self, priority_flag: PriorityFlag) -> Self {
        self.priority_flag = Some(priority_flag);
        self
    }

    pub fn schedule_delivery_time(mut self, schedule_delivery_time: ScheduleDeliveryTime) -> Self {
        self.schedule_delivery_time = Some(schedule_delivery_time);
        self
    }

    pub fn validity_period(mut self, validity_period: ValidityPeriod) -> Self {
        self.validity_period = Some(validity_period);
        self
    }

    pub fn data_coding(mut self, data_coding: DataCoding) -> Self {
        self.data_coding = Some(data_coding);
        self
    }

    pub fn broadcast_area_identifier(mut self, broadcast_area_identifier: Vec<u8>) -> Self {
        self.broadcast_area_identifier = Some(broadcast_area_identifier);
        self
    }

    pub fn broadcast_content_type(mut self, broadcast_content_type: u8) -> Self {
        self.broadcast_content_type = Some(broadcast_content_type);
        self
    }

    pub fn broadcast_rep_num(mut self, broadcast_rep_num: u16) -> Self {
        self.broadcast_rep_num = Some(broadcast_rep_num);
        self
    }

    pub fn broadcast_frequency_interval(mut self, broadcast_frequency_interval: u32) -> Self {
        self.broadcast_frequency_interval = Some(broadcast_frequency_interval);
        self
    }

    pub fn build(self) -> Result<BroadcastSm, BroadcastSmValidationError> {
        let broadcast_area_identifier = self
            .broadcast_area_identifier
            .unwrap_or_default();

        if broadcast_area_identifier.is_empty() {
            return Err(BroadcastSmValidationError::EmptyBroadcastAreaIdentifier);
        }

        let broadcast_rep_num = self.broadcast_rep_num.unwrap_or(1);
        if broadcast_rep_num == 0 {
            return Err(BroadcastSmValidationError::InvalidBroadcastRepNum);
        }

        let message_id_str = self.message_id.unwrap_or_default();
        if message_id_str.len() > 64 {
            return Err(BroadcastSmValidationError::MessageIdTooLong);
        }

        Ok(BroadcastSm {
            command_status: CommandStatus::Ok,
            sequence_number: self.sequence_number.unwrap_or(1),
            service_type: self.service_type.unwrap_or_default(),
            source_addr_ton: self.source_addr_ton.unwrap_or(TypeOfNumber::Unknown),
            source_addr_npi: self.source_addr_npi.unwrap_or(NumericPlanIndicator::Unknown),
            source_addr: self.source_addr.unwrap_or_default(),
            message_id: MessageId::from(message_id_str.as_str()),
            priority_flag: self.priority_flag.unwrap_or(PriorityFlag::Level0),
            schedule_delivery_time: self.schedule_delivery_time.unwrap_or_else(|| {
                ScheduleDeliveryTime::immediate()
            }),
            validity_period: self.validity_period.unwrap_or_else(|| {
                ValidityPeriod::immediate()
            }),
            data_coding: self.data_coding.unwrap_or_default(),
            broadcast_area_identifier,
            broadcast_content_type: self.broadcast_content_type.unwrap_or(0),
            broadcast_rep_num,
            broadcast_frequency_interval: self.broadcast_frequency_interval.unwrap_or(3600),
        })
    }
}

impl Decodable for BroadcastSm {
    fn decode(header: crate::codec::PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory parameters according to SMPP v5.0 broadcast_sm specification
        
        // service_type (6 octets, null-terminated with padding)
        let service_type_str = decode_cstring(buf, 6, "service_type")?;
        let service_type = ServiceType::from(service_type_str.as_str());

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

        // message_id (65 octets, null-terminated with padding)
        let message_id_str = decode_cstring(buf, 65, "message_id")?;
        let message_id = MessageId::from(message_id_str.as_str());

        // priority_flag (1 octet)
        let priority_flag = PriorityFlag::try_from(decode_u8(buf)?)
            .map_err(|_| CodecError::FieldValidation {
                field: "priority_flag",
                reason: "Invalid priority flag".to_string(),
            })?;

        // schedule_delivery_time (17 octets, null-terminated with padding)
        let schedule_delivery_time_str = decode_cstring(buf, 17, "schedule_delivery_time")?;
        let schedule_delivery_time = ScheduleDeliveryTime::from(schedule_delivery_time_str.as_str());

        // validity_period (17 octets, null-terminated with padding)
        let validity_period_str = decode_cstring(buf, 17, "validity_period")?;
        let validity_period = ValidityPeriod::from(validity_period_str.as_str());

        // data_coding (1 octet)
        let data_coding = DataCoding::try_from(decode_u8(buf)?)
            .map_err(|_| CodecError::FieldValidation {
                field: "data_coding",
                reason: "Invalid data coding".to_string(),
            })?;

        // broadcast_area_identifier_len (1 octet)
        let broadcast_area_identifier_len = decode_u8(buf)? as usize;

        // broadcast_area_identifier (variable length)
        if buf.remaining() < broadcast_area_identifier_len {
            return Err(CodecError::Incomplete);
        }
        let mut broadcast_area_identifier = vec![0u8; broadcast_area_identifier_len];
        buf.copy_to_slice(&mut broadcast_area_identifier);

        // broadcast_content_type (1 octet)
        let broadcast_content_type = decode_u8(buf)?;

        // broadcast_rep_num (2 octets)
        let broadcast_rep_num = decode_u16(buf)?;

        // broadcast_frequency_interval (4 octets)
        let broadcast_frequency_interval = decode_u32(buf)?;

        Ok(BroadcastSm {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            service_type,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            message_id,
            priority_flag,
            schedule_delivery_time,
            validity_period,
            data_coding,
            broadcast_area_identifier,
            broadcast_content_type,
            broadcast_rep_num,
            broadcast_frequency_interval,
        })
    }

    fn command_id() -> CommandId {
        CommandId::BroadcastSm
    }
}

impl Encodable for BroadcastSm {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Encode PDU header
        buf.put_u32(0); // command_length (will be set by to_bytes)
        buf.put_u32(Self::command_id() as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Encode mandatory parameters according to SMPP v5.0 broadcast_sm specification
        
        // service_type (6 octets, null-terminated with padding)
        encode_cstring(buf, &self.service_type.to_string(), 6);

        // source_addr_ton (1 octet)
        encode_u8(buf, self.source_addr_ton as u8);

        // source_addr_npi (1 octet)
        encode_u8(buf, self.source_addr_npi as u8);

        // source_addr (21 octets, null-terminated with padding)
        encode_cstring(buf, &self.source_addr, 21);

        // message_id (65 octets, null-terminated with padding)
        encode_cstring(buf, self.message_id.as_str().unwrap_or(""), 65);

        // priority_flag (1 octet)
        encode_u8(buf, self.priority_flag as u8);

        // schedule_delivery_time (17 octets, null-terminated with padding)
        encode_cstring(buf, self.schedule_delivery_time.as_str().unwrap_or(""), 17);

        // validity_period (17 octets, null-terminated with padding)
        encode_cstring(buf, self.validity_period.as_str().unwrap_or(""), 17);

        // data_coding (1 octet)
        encode_u8(buf, u8::from(self.data_coding));

        // broadcast_area_identifier_len (1 octet)
        encode_u8(buf, self.broadcast_area_identifier.len() as u8);

        // broadcast_area_identifier (variable length)
        buf.put_slice(&self.broadcast_area_identifier);

        // broadcast_content_type (1 octet)
        encode_u8(buf, self.broadcast_content_type);

        // broadcast_rep_num (2 octets)
        encode_u16(buf, self.broadcast_rep_num);

        // broadcast_frequency_interval (4 octets)
        encode_u32(buf, self.broadcast_frequency_interval);

        Ok(())
    }
}

impl Decodable for BroadcastSmResponse {
    fn decode(header: crate::codec::PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory parameters according to SMPP v5.0 broadcast_sm_resp specification
        
        // message_id (65 octets, null-terminated with padding)
        let message_id_str = decode_cstring(buf, 65, "message_id")?;
        let message_id = MessageId::from(message_id_str.as_str());

        Ok(BroadcastSmResponse {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            message_id,
        })
    }

    fn command_id() -> CommandId {
        CommandId::BroadcastSmResp
    }
}

impl Encodable for BroadcastSmResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Encode PDU header
        buf.put_u32(0); // command_length (will be set by to_bytes)
        buf.put_u32(Self::command_id() as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Encode mandatory parameters according to SMPP v5.0 broadcast_sm_resp specification
        
        // message_id (65 octets, null-terminated with padding)
        encode_cstring(buf, self.message_id.as_str().unwrap_or(""), 65);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcast_sm_builder() {
        let result = BroadcastSm::builder()
            .sequence_number(1)
            .message_id("TEST123")
            .broadcast_area_identifier(vec![0x01, 0x02, 0x03, 0x04])
            .broadcast_rep_num(1)
            .broadcast_frequency_interval(3600)
            .build();

        assert!(result.is_ok());
        let pdu = result.unwrap();
        assert_eq!(pdu.sequence_number(), 1);
        assert_eq!(pdu.message_id(), "TEST123");
    }

    #[test]
    fn test_broadcast_sm_validation() {
        // Test empty broadcast_area_identifier
        let result = BroadcastSm::builder()
            .broadcast_area_identifier(vec![])
            .build();
        assert!(result.is_err());

        // Test zero broadcast_rep_num
        let result = BroadcastSm::builder()
            .broadcast_area_identifier(vec![0x01])
            .broadcast_rep_num(0)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_broadcast_sm_response() {
        let response = BroadcastSmResponse::new(42, CommandStatus::Ok, "MSG123");
        assert_eq!(response.sequence_number(), 42);
        assert_eq!(response.command_status(), CommandStatus::Ok);
        assert_eq!(response.message_id(), "MSG123");
    }
}