// SMPP v3.4 Codec - Separates parsing/encoding logic from domain models
//
// This module provides a clean separation between the wire format (codec)
// and the domain models (PDUs). Each PDU implements Encodable/Decodable traits
// rather than having all parsing logic in a monolithic frame parser.

use crate::datatypes::{CommandId, CommandStatus};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::io::Cursor;
use thiserror::Error;

// Frame and registry types are defined in this file

/// Maximum allowed PDU size to prevent memory exhaustion attacks
pub const MAX_PDU_SIZE: u32 = 65536; // 64KB

/// SMPP v3.4 PDU Header (16 bytes, common to all PDUs)
#[derive(Debug, Clone, PartialEq)]
pub struct PduHeader {
    pub command_length: u32,
    pub command_id: CommandId,
    pub command_status: CommandStatus,
    pub sequence_number: u32,
}

impl PduHeader {
    pub const SIZE: usize = 16;

    /// Decode PDU header from buffer with validation
    pub fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        if buf.remaining() < Self::SIZE {
            return Err(CodecError::Incomplete);
        }

        let command_length = buf.get_u32();
        let command_id_raw = buf.get_u32();
        let command_id = CommandId::try_from(command_id_raw)
            .map_err(|_| CodecError::InvalidCommandId(command_id_raw))?;
        let command_status = CommandStatus::try_from(buf.get_u32())
            .map_err(|_| CodecError::InvalidCommandStatus(buf.get_u32()))?;
        let sequence_number = buf.get_u32();

        // Validate PDU size constraints
        if command_length < Self::SIZE as u32 {
            return Err(CodecError::InvalidPduLength {
                length: command_length,
                min: Self::SIZE as u32,
                max: MAX_PDU_SIZE,
            });
        }

        if command_length > MAX_PDU_SIZE {
            return Err(CodecError::InvalidPduLength {
                length: command_length,
                min: Self::SIZE as u32,
                max: MAX_PDU_SIZE,
            });
        }

        // Validate SMPP v3.4 rule: requests must have command_status = 0
        if !command_id.is_response() && command_status != CommandStatus::Ok {
            return Err(CodecError::InvalidRequestStatus {
                command_id,
                command_status,
            });
        }

        // Validate reserved sequence numbers
        if sequence_number == 0 || sequence_number == 0xFFFFFFFF {
            return Err(CodecError::ReservedSequenceNumber(sequence_number));
        }

        Ok(PduHeader {
            command_length,
            command_id,
            command_status,
            sequence_number,
        })
    }

    /// Encode PDU header to buffer
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        buf.put_u32(self.command_length);
        buf.put_u32(self.command_id as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);
        Ok(())
    }
}

/// Trait for types that can be encoded to bytes
pub trait Encodable {
    /// Encode this PDU to the buffer
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError>;

    /// Calculate the encoded size without actually encoding
    fn encoded_size(&self) -> usize {
        let mut buf = BytesMut::new();
        self.encode(&mut buf).map(|_| buf.len()).unwrap_or(0)
    }

    /// Convert this PDU to bytes (convenience method)
    ///
    /// This is a default implementation that creates a buffer, encodes into it,
    /// fixes the command_length field, and returns the frozen bytes. This replaces the legacy ToBytes trait.
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        self.encode(&mut buf)
            .expect("Encoding should not fail for valid PDU");

        // Fix the command_length field in the header (first 4 bytes)
        if buf.len() >= 4 {
            let length = buf.len() as u32;
            buf[0..4].copy_from_slice(&length.to_be_bytes());
        }

        buf.freeze()
    }
}

/// Trait for types that can be decoded from bytes
pub trait Decodable: Sized {
    /// Decode this PDU from the buffer after header
    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError>;

    /// Return the expected command_id for this PDU type
    fn command_id() -> CommandId;

    /// Validate the header is appropriate for this PDU type
    fn validate_header(header: &PduHeader) -> Result<(), CodecError> {
        if header.command_id != Self::command_id() {
            return Err(CodecError::UnexpectedCommandId {
                expected: Self::command_id(),
                actual: header.command_id,
            });
        }
        Ok(())
    }
}

/// Codec errors with detailed context for debugging
#[derive(Debug, Error)]
pub enum CodecError {
    #[error("Incomplete PDU: need more data")]
    Incomplete,

    #[error("Invalid command_id: {0:#x}")]
    InvalidCommandId(u32),

    #[error("Invalid command_status: {0:#x}")]
    InvalidCommandStatus(u32),

    #[error("Invalid PDU length: {length}, must be {min}-{max}")]
    InvalidPduLength { length: u32, min: u32, max: u32 },

    #[error("Request PDU {command_id:?} has non-zero status: {command_status:?}")]
    InvalidRequestStatus {
        command_id: CommandId,
        command_status: CommandStatus,
    },

    #[error("Reserved sequence number: {0} (0 and 0xFFFFFFFF are reserved)")]
    ReservedSequenceNumber(u32),

    #[error("Unexpected command_id: expected {expected:?}, got {actual:?}")]
    UnexpectedCommandId {
        expected: CommandId,
        actual: CommandId,
    },

    #[error("Field '{field}' validation failed: {reason}")]
    FieldValidation { field: &'static str, reason: String },

    #[error("TLV parsing error: {0}")]
    TlvError(String),

    #[error("UTF-8 decoding error in field '{field}': {source}")]
    Utf8Error {
        field: &'static str,
        #[source]
        source: std::string::FromUtf8Error,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl CommandId {
    /// Check if this command_id represents a response PDU
    pub fn is_response(&self) -> bool {
        (*self as u32) & 0x8000_0000 != 0
    }
}

/// Convert codec errors to appropriate SMPP command_status codes
impl CodecError {
    pub fn to_command_status(&self) -> CommandStatus {
        match self {
            CodecError::InvalidPduLength { .. } => CommandStatus::InvalidCommandLength,
            CodecError::InvalidCommandId(_) => CommandStatus::InvalidCommandId,
            CodecError::FieldValidation { field, .. } => {
                // Map specific field errors to appropriate status codes
                match *field {
                    "source_addr" | "destination_addr" => CommandStatus::InvalidSourceAddress,
                    "short_message" => CommandStatus::InvalidMsgLength,
                    _ => CommandStatus::SystemError,
                }
            }
            CodecError::TlvError(_) => CommandStatus::SystemError, // Could add specific TLV error code
            _ => CommandStatus::SystemError,
        }
    }
}

/// Utility functions for decoding common SMPP field types
pub fn decode_cstring(
    buf: &mut Cursor<&[u8]>,
    max_len: usize,
    field_name: &'static str,
) -> Result<String, CodecError> {
    if buf.remaining() < max_len {
        return Err(CodecError::Incomplete);
    }

    // Read the fixed-size field
    let field_bytes = buf.copy_to_bytes(max_len);

    // Find null terminator or use entire field
    let end = field_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(field_bytes.len());

    // Convert to string, handling potential non-UTF8 data gracefully
    String::from_utf8(field_bytes[..end].to_vec()).map_err(|e| CodecError::Utf8Error {
        field: field_name,
        source: e,
    })
}

/// Decode a single byte
pub fn decode_u8(buf: &mut Cursor<&[u8]>) -> Result<u8, CodecError> {
    if buf.remaining() < 1 {
        return Err(CodecError::Incomplete);
    }
    Ok(buf.get_u8())
}

/// Decode a 16-bit big-endian integer
pub fn decode_u16(buf: &mut Cursor<&[u8]>) -> Result<u16, CodecError> {
    if buf.remaining() < 2 {
        return Err(CodecError::Incomplete);
    }
    Ok(buf.get_u16())
}

/// Decode a 32-bit big-endian integer
pub fn decode_u32(buf: &mut Cursor<&[u8]>) -> Result<u32, CodecError> {
    if buf.remaining() < 4 {
        return Err(CodecError::Incomplete);
    }
    Ok(buf.get_u32())
}

/// Peek at next 4 bytes without advancing cursor (for command_length)
pub fn peek_u32(buf: &mut Cursor<&[u8]>) -> Result<u32, CodecError> {
    if buf.remaining() < 4 {
        return Err(CodecError::Incomplete);
    }

    let pos = buf.position();
    let value = buf.get_u32();
    buf.set_position(pos); // Reset position
    Ok(value)
}

/// Utility functions for encoding common SMPP field types
pub fn encode_cstring(buf: &mut BytesMut, value: &str, max_len: usize) {
    let bytes = value.as_bytes();
    let actual_len = bytes.len().min(max_len - 1); // Reserve space for null terminator

    // Write the string content
    buf.put_slice(&bytes[..actual_len]);

    // Add null terminator
    buf.put_u8(0);

    // Pad with zeros to reach max_len
    let padding_needed = max_len - actual_len - 1;
    for _ in 0..padding_needed {
        buf.put_u8(0);
    }
}

/// Encode a single byte
pub fn encode_u8(buf: &mut BytesMut, value: u8) {
    buf.put_u8(value);
}

/// Encode a 16-bit big-endian integer
pub fn encode_u16(buf: &mut BytesMut, value: u16) {
    buf.put_u16(value);
}

/// Encode a 32-bit big-endian integer
pub fn encode_u32(buf: &mut BytesMut, value: u32) {
    buf.put_u32(value);
}

/// Generic frame type that can hold any PDU
#[derive(Debug)]
pub enum Frame {
    // Keep-alive PDUs
    EnquireLink(crate::datatypes::EnquireLink),
    EnquireLinkResp(crate::datatypes::EnquireLinkResponse),

    // Session management PDUs
    Unbind(crate::datatypes::Unbind),
    UnbindResp(crate::datatypes::UnbindResponse),

    // Bind PDUs
    // TODO: Add codec implementations for these PDUs
    // BindReceiver(crate::datatypes::BindReceiver),
    // BindReceiverResponse(crate::datatypes::BindReceiverResponse),
    // BindTransceiver(crate::datatypes::BindTransceiver),
    // BindTransceiverResponse(crate::datatypes::BindTransceiverResponse),
    BindTransmitter(crate::datatypes::BindTransmitter),
    // BindTransmitterResponse(crate::datatypes::BindTransmitterResponse),

    // Message PDUs
    SubmitSm(Box<crate::datatypes::SubmitSm>),
    SubmitSmResp(crate::datatypes::SubmitSmResponse),
    SubmitMulti(Box<crate::datatypes::SubmitMulti>),
    SubmitMultiResp(crate::datatypes::SubmitMultiResponse),
    QuerySm(crate::datatypes::QuerySm),
    QuerySmResp(crate::datatypes::QuerySmResponse),
    ReplaceSm(Box<crate::datatypes::ReplaceSm>),
    ReplaceSmResp(crate::datatypes::ReplaceSmResponse),
    CancelSm(crate::datatypes::CancelSm),
    CancelSmResp(crate::datatypes::CancelSmResponse),
    DataSm(Box<crate::datatypes::DataSm>),
    DataSmResp(crate::datatypes::DataSmResponse),
    // TODO: Add codec implementations for these PDUs
    // DeliverSm(Box<crate::datatypes::DeliverSm>),
    // DeliverSmResponse(crate::datatypes::DeliverSmResponse),

    // Notification PDUs
    AlertNotification(crate::datatypes::AlertNotification),

    // Special PDUs
    GenericNack(crate::datatypes::GenericNack),
    Outbind(crate::datatypes::Outbind),

    // For unknown PDUs (forward compatibility)
    Unknown { header: PduHeader, body: Bytes },
}

/// Registry of PDU decoders for extensible parsing
type DecoderFn =
    Box<dyn Fn(PduHeader, &mut Cursor<&[u8]>) -> Result<Frame, CodecError> + Send + Sync>;

pub struct PduRegistry {
    decoders: HashMap<CommandId, DecoderFn>,
}

impl PduRegistry {
    /// Create a new registry with standard SMPP v3.4 PDUs registered
    pub fn new() -> Self {
        let mut registry = Self {
            decoders: HashMap::new(),
        };

        // Register simple PDUs
        registry.register_pdu::<crate::datatypes::EnquireLink, _>(Frame::EnquireLink);
        registry.register_pdu::<crate::datatypes::EnquireLinkResponse, _>(Frame::EnquireLinkResp);
        registry.register_pdu::<crate::datatypes::Unbind, _>(Frame::Unbind);
        registry.register_pdu::<crate::datatypes::UnbindResponse, _>(Frame::UnbindResp);
        registry.register_pdu::<crate::datatypes::GenericNack, _>(Frame::GenericNack);
        registry.register_pdu::<crate::datatypes::Outbind, _>(Frame::Outbind);

        // Register bind PDUs
        registry.register_pdu::<crate::datatypes::BindTransmitter, _>(Frame::BindTransmitter);

        // Register message PDUs (boxed for large structs)
        registry.register_boxed_pdu::<crate::datatypes::SubmitSm, _>(|pdu| {
            Frame::SubmitSm(Box::new(pdu))
        });
        registry.register_pdu::<crate::datatypes::SubmitSmResponse, _>(Frame::SubmitSmResp);

        // Register submit_multi PDUs
        registry.register_boxed_pdu::<crate::datatypes::SubmitMulti, _>(|pdu| {
            Frame::SubmitMulti(Box::new(pdu))
        });
        registry.register_pdu::<crate::datatypes::SubmitMultiResponse, _>(Frame::SubmitMultiResp);

        // Register query PDUs
        registry.register_pdu::<crate::datatypes::QuerySm, _>(Frame::QuerySm);
        registry.register_pdu::<crate::datatypes::QuerySmResponse, _>(Frame::QuerySmResp);

        // Register replace PDUs
        registry.register_boxed_pdu::<crate::datatypes::ReplaceSm, _>(|pdu| {
            Frame::ReplaceSm(Box::new(pdu))
        });
        registry.register_pdu::<crate::datatypes::ReplaceSmResponse, _>(Frame::ReplaceSmResp);

        // Register cancel PDUs
        registry.register_pdu::<crate::datatypes::CancelSm, _>(Frame::CancelSm);
        registry.register_pdu::<crate::datatypes::CancelSmResponse, _>(Frame::CancelSmResp);

        // Register data_sm PDUs
        registry.register_boxed_pdu::<crate::datatypes::DataSm, _>(|pdu| {
            Frame::DataSm(Box::new(pdu))
        });
        registry.register_pdu::<crate::datatypes::DataSmResponse, _>(Frame::DataSmResp);

        // Register notification PDUs
        registry.register_pdu::<crate::datatypes::AlertNotification, _>(Frame::AlertNotification);

        registry
    }

    /// Register a simple PDU type (no boxing required)
    fn register_pdu<T, F>(&mut self, frame_constructor: F)
    where
        T: Decodable + 'static,
        F: Fn(T) -> Frame + Send + Sync + 'static,
    {
        let command_id = T::command_id();
        let decoder = Box::new(move |header: PduHeader, buf: &mut Cursor<&[u8]>| {
            let pdu = T::decode(header, buf)?;
            Ok(frame_constructor(pdu))
        });
        self.decoders.insert(command_id, decoder);
    }

    /// Register a PDU type that should be boxed
    fn register_boxed_pdu<T, F>(&mut self, frame_constructor: F)
    where
        T: Decodable + 'static,
        F: Fn(T) -> Frame + Send + Sync + 'static,
    {
        let command_id = T::command_id();
        let decoder = Box::new(move |header: PduHeader, buf: &mut Cursor<&[u8]>| {
            let pdu = T::decode(header, buf)?;
            Ok(frame_constructor(pdu))
        });
        self.decoders.insert(command_id, decoder);
    }

    /// Decode a PDU given its header and body
    pub fn decode_pdu(
        &self,
        header: PduHeader,
        buf: &mut Cursor<&[u8]>,
    ) -> Result<Frame, CodecError> {
        match self.decoders.get(&header.command_id) {
            Some(decoder) => decoder(header, buf),
            None => {
                // Handle unknown PDU gracefully for forward compatibility
                let body_size = header.command_length as usize - PduHeader::SIZE;
                if buf.remaining() < body_size {
                    return Err(CodecError::Incomplete);
                }

                let body = buf.copy_to_bytes(body_size);
                tracing::warn!(
                    "Unknown PDU command_id: {:#x}, treating as opaque data",
                    header.command_id as u32
                );

                Ok(Frame::Unknown { header, body })
            }
        }
    }

    /// Check if a command_id is registered
    pub fn is_registered(&self, command_id: CommandId) -> bool {
        self.decoders.contains_key(&command_id)
    }

    /// Get all registered command_ids
    pub fn registered_commands(&self) -> Vec<CommandId> {
        self.decoders.keys().copied().collect()
    }
}

impl Default for PduRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Frame {
    /// Get the command_id for this frame
    pub fn command_id(&self) -> CommandId {
        match self {
            Frame::EnquireLink(_) => CommandId::EnquireLink,
            Frame::EnquireLinkResp(_) => CommandId::EnquireLinkResp,
            Frame::Unbind(_) => CommandId::Unbind,
            Frame::UnbindResp(_) => CommandId::UnbindResp,
            Frame::BindTransmitter(_) => CommandId::BindTransmitter,
            Frame::SubmitSm(_) => CommandId::SubmitSm,
            Frame::SubmitSmResp(_) => CommandId::SubmitSmResp,
            Frame::SubmitMulti(_) => CommandId::SubmitMulti,
            Frame::SubmitMultiResp(_) => CommandId::SubmitMultiResp,
            Frame::QuerySm(_) => CommandId::QuerySm,
            Frame::QuerySmResp(_) => CommandId::QuerySmResp,
            Frame::ReplaceSm(_) => CommandId::ReplaceSm,
            Frame::ReplaceSmResp(_) => CommandId::ReplaceSmResp,
            Frame::CancelSm(_) => CommandId::CancelSm,
            Frame::CancelSmResp(_) => CommandId::CancelSmResp,
            Frame::DataSm(_) => CommandId::DataSm,
            Frame::DataSmResp(_) => CommandId::DataSmResp,
            Frame::AlertNotification(_) => CommandId::AlertNotification,
            Frame::GenericNack(_) => CommandId::GenericNack,
            Frame::Outbind(_) => CommandId::Outbind,
            Frame::Unknown { header, .. } => header.command_id,
        }
    }

    /// Get the sequence number for this frame
    pub fn sequence_number(&self) -> u32 {
        match self {
            Frame::EnquireLink(pdu) => pdu.sequence_number,
            Frame::EnquireLinkResp(pdu) => pdu.sequence_number,
            Frame::Unbind(pdu) => pdu.sequence_number,
            Frame::UnbindResp(pdu) => pdu.sequence_number,
            Frame::BindTransmitter(pdu) => pdu.sequence_number,
            Frame::SubmitSm(pdu) => pdu.sequence_number,
            Frame::SubmitSmResp(pdu) => pdu.sequence_number,
            Frame::SubmitMulti(pdu) => pdu.sequence_number,
            Frame::SubmitMultiResp(pdu) => pdu.sequence_number,
            Frame::QuerySm(pdu) => pdu.sequence_number,
            Frame::QuerySmResp(pdu) => pdu.sequence_number,
            Frame::ReplaceSm(pdu) => pdu.sequence_number,
            Frame::ReplaceSmResp(pdu) => pdu.sequence_number,
            Frame::CancelSm(pdu) => pdu.sequence_number,
            Frame::CancelSmResp(pdu) => pdu.sequence_number,
            Frame::DataSm(pdu) => pdu.sequence_number,
            Frame::DataSmResp(pdu) => pdu.sequence_number,
            Frame::AlertNotification(pdu) => pdu.sequence_number,
            Frame::GenericNack(pdu) => pdu.sequence_number,
            Frame::Outbind(pdu) => pdu.sequence_number,
            Frame::Unknown { header, .. } => header.sequence_number,
        }
    }

    /// Check if this frame is a response PDU
    pub fn is_response(&self) -> bool {
        self.command_id().is_response()
    }

    /// Legacy check method for backward compatibility
    pub fn check(buf: &mut Cursor<&[u8]>) -> Result<(), crate::frame::Error> {
        // Check if we have enough bytes for a header
        if buf.remaining() < PduHeader::SIZE {
            return Err(crate::frame::Error::Incomplete);
        }

        // Peek at command_length without advancing cursor
        let pos = buf.position();
        let command_length = buf.get_u32();
        buf.set_position(pos);

        // Validate length
        if command_length < PduHeader::SIZE as u32 {
            return Err(crate::frame::Error::Other(Box::new(
                CodecError::InvalidPduLength {
                    length: command_length,
                    min: PduHeader::SIZE as u32,
                    max: MAX_PDU_SIZE,
                },
            )));
        }

        // Check if we have the complete PDU
        if buf.remaining() < command_length as usize {
            return Err(crate::frame::Error::Incomplete);
        }

        Ok(())
    }

    /// Legacy parse method for backward compatibility
    pub fn parse(buf: &mut Cursor<&[u8]>) -> Result<Frame, crate::frame::Error> {
        let registry = PduRegistry::new();

        // Decode header
        let header = PduHeader::decode(buf)?;

        // Decode PDU using registry
        let frame = registry.decode_pdu(header, buf)?;

        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datatypes::{
        CommandStatus, EnquireLink, EnquireLinkResponse, GenericNack, Outbind, Password, SystemId,
        Unbind,
    };

    #[test]
    fn pdu_header_encode_decode() {
        let header = PduHeader {
            command_length: 24,
            command_id: CommandId::EnquireLink,
            command_status: CommandStatus::Ok,
            sequence_number: 42,
        };

        let mut buf = BytesMut::new();
        let _ = header.encode(&mut buf);

        let mut cursor = Cursor::new(buf.as_ref());
        let decoded = PduHeader::decode(&mut cursor).unwrap();

        assert_eq!(header, decoded);
    }

    #[test]
    fn decode_cstring_normal() {
        let data = b"hello\0\0\0\0\0"; // 5 chars + null, padded to 10
        let mut cursor = Cursor::new(&data[..]);
        let result = decode_cstring(&mut cursor, 10, "test").unwrap();
        assert_eq!(result, "hello");
        assert_eq!(cursor.position(), 10);
    }

    #[test]
    fn encode_cstring_normal() {
        let mut buf = BytesMut::new();
        encode_cstring(&mut buf, "hello", 10);

        let expected = b"hello\0\0\0\0\0";
        assert_eq!(buf.as_ref(), expected);
        assert_eq!(buf.len(), 10);
    }

    #[test]
    fn enquire_link_roundtrip_new_codec() {
        let original = EnquireLink::new(42);

        // Encode using new trait
        let encoded_bytes = original.to_bytes();

        // Decode using new trait
        let mut cursor = Cursor::new(encoded_bytes.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();
        let decoded = EnquireLink::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn enquire_link_response_roundtrip_new_codec() {
        let original = EnquireLinkResponse::error(123, CommandStatus::SystemError);

        // Encode using new trait
        let encoded_bytes = original.to_bytes();

        // Decode using new trait
        let mut cursor = Cursor::new(encoded_bytes.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();
        let decoded = EnquireLinkResponse::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn registry_decode_enquire_link() {
        let registry = PduRegistry::new();
        let enquire_link = EnquireLink::new(42);

        // Encode to bytes
        let encoded_bytes = enquire_link.to_bytes();

        // Decode header
        let mut cursor = Cursor::new(encoded_bytes.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();

        // Decode PDU using registry
        let frame = registry.decode_pdu(header, &mut cursor).unwrap();

        match frame {
            Frame::EnquireLink(decoded) => {
                assert_eq!(decoded.sequence_number, 42);
                assert_eq!(decoded.command_status, CommandStatus::Ok);
            }
            _ => panic!("Expected EnquireLink frame"),
        }
    }

    #[test]
    #[ignore] // TODO: Fix unknown PDU handling - need to update CommandId enum
    fn registry_decode_unknown_pdu() {
        let registry = PduRegistry::new();

        // Use an actually reserved command_id (0x0000000A is reserved per spec)
        let unknown_command_id = 0x0000000Au32;

        // Create a complete PDU with unknown command_id
        let mut pdu_data = Vec::new();
        pdu_data.extend_from_slice(&20u32.to_be_bytes()); // command_length
        pdu_data.extend_from_slice(&unknown_command_id.to_be_bytes()); // command_id
        pdu_data.extend_from_slice(&0u32.to_be_bytes()); // command_status
        pdu_data.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
        pdu_data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // body

        let mut cursor = Cursor::new(pdu_data.as_slice());

        // First decode the header
        let header = PduHeader::decode(&mut cursor).unwrap();

        // Should handle unknown PDU gracefully
        let frame = registry.decode_pdu(header.clone(), &mut cursor).unwrap();

        match frame {
            Frame::Unknown { header: h, body } => {
                assert_eq!(h.command_id as u32, unknown_command_id);
                assert_eq!(body.as_ref(), &[0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("Expected Unknown frame for unregistered PDU"),
        }
    }

    #[test]
    fn pdu_header_validation() {
        // Test PDU length validation
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x08, // command_length too small
            0x00, 0x00, 0x00, 0x15, // command_id
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
        ];
        let mut cursor = Cursor::new(data);

        let result = PduHeader::decode(&mut cursor);
        assert!(matches!(result, Err(CodecError::InvalidPduLength { .. })));

        // Test reserved sequence number validation
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x10, // command_length
            0x00, 0x00, 0x00, 0x15, // command_id
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x00, // sequence_number (reserved)
        ];
        let mut cursor = Cursor::new(data);

        let result = PduHeader::decode(&mut cursor);
        assert!(matches!(result, Err(CodecError::ReservedSequenceNumber(0))));
    }

    #[test]
    fn command_id_is_response() {
        assert!(!CommandId::EnquireLink.is_response());
        assert!(CommandId::EnquireLinkResp.is_response());
        assert!(!CommandId::SubmitSm.is_response());
        assert!(CommandId::SubmitSmResp.is_response());
    }

    #[test]
    fn frame_accessors() {
        let enquire_link = EnquireLink::new(42);
        let frame = Frame::EnquireLink(enquire_link);

        assert_eq!(frame.command_id(), CommandId::EnquireLink);
        assert_eq!(frame.sequence_number(), 42);
        assert!(!frame.is_response());

        let response = EnquireLinkResponse::new(43);
        let frame = Frame::EnquireLinkResp(response);

        assert_eq!(frame.command_id(), CommandId::EnquireLinkResp);
        assert_eq!(frame.sequence_number(), 43);
        assert!(frame.is_response());
    }

    #[test]
    fn unbind_roundtrip_new_codec() {
        let original = Unbind::new(123);

        // Encode using new trait
        let encoded_bytes = original.to_bytes();

        // Decode using new trait
        let mut cursor = Cursor::new(encoded_bytes.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();
        let decoded = Unbind::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn generic_nack_roundtrip_new_codec() {
        let original = GenericNack::invalid_command_id(456);

        // Encode using new trait
        let encoded_bytes = original.to_bytes();

        // Decode using new trait
        let mut cursor = Cursor::new(encoded_bytes.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();
        let decoded = GenericNack::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn outbind_roundtrip_new_codec() {
        let original = Outbind::new(789, SystemId::from("TEST"), Some(Password::from("secret")));

        // Encode using new trait
        let encoded_bytes = original.to_bytes();

        // Decode using new trait
        let mut cursor = Cursor::new(encoded_bytes.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();
        let decoded = Outbind::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn registry_decode_all_simple_pdus() {
        let registry = PduRegistry::new();

        // Test EnquireLink
        let enquire = EnquireLink::new(1);
        let bytes = enquire.to_bytes();
        let mut cursor = Cursor::new(bytes.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();
        let frame = registry.decode_pdu(header, &mut cursor).unwrap();
        assert!(matches!(frame, Frame::EnquireLink(_)));

        // Test Unbind
        let unbind = Unbind::new(2);
        let bytes = unbind.to_bytes();
        let mut cursor = Cursor::new(bytes.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();
        let frame = registry.decode_pdu(header, &mut cursor).unwrap();
        assert!(matches!(frame, Frame::Unbind(_)));

        // Test GenericNack
        let nack = GenericNack::system_error(3);
        let bytes = nack.to_bytes();
        let mut cursor = Cursor::new(bytes.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();
        let frame = registry.decode_pdu(header, &mut cursor).unwrap();
        assert!(matches!(frame, Frame::GenericNack(_)));

        // Test Outbind
        let outbind = Outbind::new(4, SystemId::from("TEST"), None);
        let bytes = outbind.to_bytes();
        let mut cursor = Cursor::new(bytes.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();
        let frame = registry.decode_pdu(header, &mut cursor).unwrap();
        assert!(matches!(frame, Frame::Outbind(_)));
    }

    #[test]
    fn registry_has_all_simple_pdus() {
        let registry = PduRegistry::new();
        let registered = registry.registered_commands();

        assert!(registered.contains(&CommandId::EnquireLink));
        assert!(registered.contains(&CommandId::EnquireLinkResp));
        assert!(registered.contains(&CommandId::Unbind));
        assert!(registered.contains(&CommandId::UnbindResp));
        assert!(registered.contains(&CommandId::GenericNack));
        assert!(registered.contains(&CommandId::Outbind));
    }
}
