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
            CodecError::InvalidCommandStatus(_) => CommandStatus::SystemError,
            CodecError::InvalidRequestStatus { .. } => CommandStatus::SystemError,
            CodecError::ReservedSequenceNumber(_) => CommandStatus::SystemError,
            CodecError::UnexpectedCommandId { .. } => CommandStatus::InvalidCommandId,
            CodecError::FieldValidation { field, reason } => {
                // Enhanced field-specific error mapping based on SMPP v3.4 specification
                match *field {
                    // Address-related fields
                    "source_addr" => CommandStatus::InvalidSourceAddress,
                    "destination_addr" => CommandStatus::InvalidDestinationAddress,
                    "esme_addr" => CommandStatus::InvalidSourceAddress,
                    
                    // TON/NPI validation errors
                    "source_addr_ton" | "addr_ton" => CommandStatus::InvalidSourceAddressTon,
                    "source_addr_npi" | "addr_npi" => CommandStatus::InvalidSourceAddressNpi,
                    "dest_addr_ton" => CommandStatus::InvalidDestinationAddressTon,
                    "dest_addr_npi" => CommandStatus::InvalidDestinationAddressNpi,
                    
                    // Message content fields
                    "short_message" => CommandStatus::InvalidMsgLength,
                    "message_payload" => CommandStatus::InvalidMsgLength,
                    "sm_length" => CommandStatus::InvalidMsgLength,
                    
                    // Authentication and identification fields
                    "system_id" => CommandStatus::InvalidSystemId,
                    "password" => CommandStatus::InvalidPassword,
                    "service_type" => CommandStatus::InvalidServiceType,
                    
                    // Message identification
                    "message_id" => CommandStatus::InvalidMessageId,
                    
                    // Message parameters
                    "priority_flag" => CommandStatus::InvalidPriorityFlag,
                    "registered_delivery" => CommandStatus::InvalidRegisteredDeliveryFlag,
                    "esm_class" => CommandStatus::InvalidEsmClassFieldData,
                    
                    // Multi-destination fields
                    "dest_flag" => CommandStatus::InvalidDestinationFlag,
                    "dl_name" => CommandStatus::InvalidDistributionListName,
                    
                    // Check for range/length validation errors in reason
                    _ => {
                        if reason.contains("too long") || reason.contains("exceeds maximum") {
                            match *field {
                                f if f.contains("addr") => CommandStatus::InvalidDestinationAddress,
                                "system_id" => CommandStatus::InvalidSystemId,
                                _ => CommandStatus::InvalidMsgLength,
                            }
                        } else if reason.contains("invalid format") || reason.contains("invalid value") {
                            CommandStatus::SystemError
                        } else {
                            CommandStatus::SystemError
                        }
                    }
                }
            }
            CodecError::TlvError(msg) => {
                // Distinguish between different TLV error types
                if msg.contains("unsupported") || msg.contains("unknown") {
                    CommandStatus::SystemError // Could be extended with specific TLV error codes
                } else if msg.contains("length") || msg.contains("size") {
                    CommandStatus::InvalidMsgLength
                } else {
                    CommandStatus::SystemError
                }
            }
            CodecError::Utf8Error { field, .. } => {
                // Text encoding errors typically indicate message content issues
                match *field {
                    "short_message" | "message_payload" => CommandStatus::InvalidMsgLength,
                    "system_id" => CommandStatus::InvalidSystemId,
                    _ => CommandStatus::SystemError,
                }
            }
            CodecError::Incomplete => CommandStatus::SystemError,
            CodecError::Io(_) => CommandStatus::SystemError,
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

    // SMPP v5.0 Broadcast PDUs
    BroadcastSm(Box<crate::datatypes::BroadcastSm>),
    BroadcastSmResp(crate::datatypes::BroadcastSmResponse),
    QueryBroadcastSm(crate::datatypes::QueryBroadcastSm),
    QueryBroadcastSmResp(crate::datatypes::QueryBroadcastSmResponse),
    CancelBroadcastSm(crate::datatypes::CancelBroadcastSm),
    CancelBroadcastSmResp(crate::datatypes::CancelBroadcastSmResponse),

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
    version: crate::datatypes::InterfaceVersion,
    supported_tlvs: std::collections::HashSet<u16>,
}

impl PduRegistry {
    /// Create a new registry with standard SMPP v3.4 PDUs registered
    pub fn new() -> Self {
        Self::for_version(crate::datatypes::InterfaceVersion::SmppV34)
    }

    /// Create a registry for a specific SMPP version
    pub fn for_version(version: crate::datatypes::InterfaceVersion) -> Self {
        let mut registry = Self {
            decoders: HashMap::new(),
            version,
            supported_tlvs: std::collections::HashSet::new(),
        };

        // Initialize supported TLVs based on version
        registry.initialize_supported_tlvs();
        registry.register_pdus_for_version();

        registry
    }

    /// Initialize supported TLVs based on SMPP version
    fn initialize_supported_tlvs(&mut self) {
        use crate::datatypes::tags;

        // Add standard v3.4 TLVs
        self.supported_tlvs.insert(tags::USER_MESSAGE_REFERENCE);
        self.supported_tlvs.insert(tags::SOURCE_PORT);
        self.supported_tlvs.insert(tags::DESTINATION_PORT);
        self.supported_tlvs.insert(tags::SAR_MSG_REF_NUM);
        self.supported_tlvs.insert(tags::SAR_TOTAL_SEGMENTS);
        self.supported_tlvs.insert(tags::SAR_SEGMENT_SEQNUM);
        self.supported_tlvs.insert(tags::MORE_MESSAGES_TO_SEND);
        self.supported_tlvs.insert(tags::PAYLOAD_TYPE);
        self.supported_tlvs.insert(tags::MESSAGE_PAYLOAD);
        self.supported_tlvs.insert(tags::PRIVACY_INDICATOR);
        self.supported_tlvs.insert(tags::CALLBACK_NUM);
        self.supported_tlvs.insert(tags::SOURCE_SUBADDRESS);
        self.supported_tlvs.insert(tags::DEST_SUBADDRESS);
        self.supported_tlvs.insert(tags::DISPLAY_TIME);
        self.supported_tlvs.insert(tags::SMS_SIGNAL);
        self.supported_tlvs.insert(tags::MS_VALIDITY);
        self.supported_tlvs.insert(tags::MS_MSG_WAIT_FACILITIES);
        self.supported_tlvs.insert(tags::NUMBER_OF_MESSAGES);
        self.supported_tlvs.insert(tags::ALERT_ON_MSG_DELIVERY);
        self.supported_tlvs.insert(tags::LANGUAGE_INDICATOR);
        self.supported_tlvs.insert(tags::ITS_REPLY_TYPE);
        self.supported_tlvs.insert(tags::ITS_SESSION_INFO);
        self.supported_tlvs.insert(tags::USSD_SERVICE_OP);

        // Add v5.0 specific TLVs
        if matches!(self.version, crate::datatypes::InterfaceVersion::SmppV50) {
            self.supported_tlvs.insert(tags::CONGESTION_STATE);
            self.supported_tlvs.insert(tags::BILLING_IDENTIFICATION);
            self.supported_tlvs.insert(tags::SOURCE_NETWORK_ID);
            self.supported_tlvs.insert(tags::DEST_NETWORK_ID);
            self.supported_tlvs.insert(tags::SOURCE_NODE_ID);
            self.supported_tlvs.insert(tags::DEST_NODE_ID);
        }
    }

    /// Register PDUs based on SMPP version
    fn register_pdus_for_version(&mut self) {
        // Register simple PDUs (common to all versions)
        self.register_pdu::<crate::datatypes::EnquireLink, _>(Frame::EnquireLink);
        self.register_pdu::<crate::datatypes::EnquireLinkResponse, _>(Frame::EnquireLinkResp);
        self.register_pdu::<crate::datatypes::Unbind, _>(Frame::Unbind);
        self.register_pdu::<crate::datatypes::UnbindResponse, _>(Frame::UnbindResp);
        self.register_pdu::<crate::datatypes::GenericNack, _>(Frame::GenericNack);
        self.register_pdu::<crate::datatypes::Outbind, _>(Frame::Outbind);

        // Register bind PDUs
        self.register_pdu::<crate::datatypes::BindTransmitter, _>(Frame::BindTransmitter);

        // Register message PDUs (boxed for large structs)
        self.register_boxed_pdu::<crate::datatypes::SubmitSm, _>(|pdu| {
            Frame::SubmitSm(Box::new(pdu))
        });
        self.register_pdu::<crate::datatypes::SubmitSmResponse, _>(Frame::SubmitSmResp);

        // Register submit_multi PDUs
        self.register_boxed_pdu::<crate::datatypes::SubmitMulti, _>(|pdu| {
            Frame::SubmitMulti(Box::new(pdu))
        });
        self.register_pdu::<crate::datatypes::SubmitMultiResponse, _>(Frame::SubmitMultiResp);

        // Register query PDUs
        self.register_pdu::<crate::datatypes::QuerySm, _>(Frame::QuerySm);
        self.register_pdu::<crate::datatypes::QuerySmResponse, _>(Frame::QuerySmResp);

        // Register replace PDUs
        self.register_boxed_pdu::<crate::datatypes::ReplaceSm, _>(|pdu| {
            Frame::ReplaceSm(Box::new(pdu))
        });
        self.register_pdu::<crate::datatypes::ReplaceSmResponse, _>(Frame::ReplaceSmResp);

        // Register cancel PDUs
        self.register_pdu::<crate::datatypes::CancelSm, _>(Frame::CancelSm);
        self.register_pdu::<crate::datatypes::CancelSmResponse, _>(Frame::CancelSmResp);

        // Register data_sm PDUs
        self.register_boxed_pdu::<crate::datatypes::DataSm, _>(|pdu| {
            Frame::DataSm(Box::new(pdu))
        });
        self.register_pdu::<crate::datatypes::DataSmResponse, _>(Frame::DataSmResp);

        // Register notification PDUs
        self.register_pdu::<crate::datatypes::AlertNotification, _>(Frame::AlertNotification);

        // Register v5.0 specific PDUs
        if matches!(self.version, crate::datatypes::InterfaceVersion::SmppV50) {
            self.register_boxed_pdu::<crate::datatypes::BroadcastSm, _>(|pdu| {
                Frame::BroadcastSm(Box::new(pdu))
            });
            self.register_pdu::<crate::datatypes::BroadcastSmResponse, _>(Frame::BroadcastSmResp);
            self.register_pdu::<crate::datatypes::QueryBroadcastSm, _>(Frame::QueryBroadcastSm);
            self.register_pdu::<crate::datatypes::QueryBroadcastSmResponse, _>(Frame::QueryBroadcastSmResp);
            self.register_pdu::<crate::datatypes::CancelBroadcastSm, _>(Frame::CancelBroadcastSm);
            self.register_pdu::<crate::datatypes::CancelBroadcastSmResponse, _>(Frame::CancelBroadcastSmResp);
        }
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

    /// Get the SMPP version this registry is configured for
    pub fn version(&self) -> crate::datatypes::InterfaceVersion {
        self.version
    }

    /// Check if this registry supports a specific SMPP version
    pub fn supports_version(&self, version: crate::datatypes::InterfaceVersion) -> bool {
        match (self.version, version) {
            // v5.0 registry can handle all previous versions
            (crate::datatypes::InterfaceVersion::SmppV50, _) => true,
            // v3.4 registry can handle v3.3 and v3.4
            (crate::datatypes::InterfaceVersion::SmppV34, crate::datatypes::InterfaceVersion::SmppV33) => true,
            (crate::datatypes::InterfaceVersion::SmppV34, crate::datatypes::InterfaceVersion::SmppV34) => true,
            // v3.3 registry only handles v3.3
            (crate::datatypes::InterfaceVersion::SmppV33, crate::datatypes::InterfaceVersion::SmppV33) => true,
            // Any other combination is not supported
            _ => false,
        }
    }

    /// Check if this registry supports a specific TLV tag
    pub fn supports_tlv(&self, tag: u16) -> bool {
        self.supported_tlvs.contains(&tag)
    }

    /// Check if this registry supports a specific feature
    pub fn supports_feature(&self, feature: &str) -> bool {
        match feature {
            // Core v3.4 features
            "submit_sm" | "deliver_sm" | "submit_multi" | "query_sm" | "replace_sm" | "cancel_sm" | "data_sm" => true,
            // v5.0 specific features
            "congestion_control" | "enhanced_billing" => {
                matches!(self.version, crate::datatypes::InterfaceVersion::SmppV50)
            }
            "broadcast_sm" => {
                matches!(self.version, crate::datatypes::InterfaceVersion::SmppV50)
            }
            _ => false,
        }
    }

    /// Upgrade this registry to support a higher SMPP version
    /// Note: Does not downgrade - preserves existing capabilities
    pub fn upgrade_to_version(&mut self, version: crate::datatypes::InterfaceVersion) {
        // Only upgrade to higher versions, never downgrade
        let should_upgrade = match (self.version, version) {
            (crate::datatypes::InterfaceVersion::SmppV33, crate::datatypes::InterfaceVersion::SmppV34) => true,
            (crate::datatypes::InterfaceVersion::SmppV33, crate::datatypes::InterfaceVersion::SmppV50) => true,
            (crate::datatypes::InterfaceVersion::SmppV34, crate::datatypes::InterfaceVersion::SmppV50) => true,
            _ => false,
        };

        if should_upgrade {
            self.version = version;
            // Re-initialize TLVs to include new version capabilities
            self.supported_tlvs.clear();
            self.initialize_supported_tlvs();
        }
    }

    /// Detect SMPP version from a bind PDU
    pub fn detect_version_from_bind(pdu_bytes: &[u8]) -> Option<crate::datatypes::InterfaceVersion> {
        use std::io::Cursor;
        
        // Minimum PDU size check (header + interface_version field)
        if pdu_bytes.len() < 16 + 15 + 9 + 13 + 1 {  // header + system_id + password + system_type + interface_version
            return None;
        }

        let mut cursor = Cursor::new(pdu_bytes);
        
        // Skip PDU header (16 bytes)
        cursor.set_position(16);
        
        // Skip system_id (16 bytes with null terminator)
        cursor.set_position(cursor.position() + 16);
        
        // Skip password (9 bytes with null terminator)
        cursor.set_position(cursor.position() + 9);
        
        // Skip system_type (13 bytes with null terminator)
        cursor.set_position(cursor.position() + 13);
        
        // Read interface_version (1 byte)
        if cursor.position() < pdu_bytes.len() as u64 {
            let interface_version = pdu_bytes[cursor.position() as usize];
            crate::datatypes::InterfaceVersion::try_from(interface_version).ok()
        } else {
            None
        }
    }

    /// Negotiate the highest common SMPP version between two versions
    pub fn negotiate_version(
        version1: crate::datatypes::InterfaceVersion,
        version2: crate::datatypes::InterfaceVersion,
    ) -> crate::datatypes::InterfaceVersion {
        use crate::datatypes::InterfaceVersion;
        
        match (version1, version2) {
            (InterfaceVersion::SmppV50, InterfaceVersion::SmppV50) => InterfaceVersion::SmppV50,
            (InterfaceVersion::SmppV34, InterfaceVersion::SmppV34) => InterfaceVersion::SmppV34,
            (InterfaceVersion::SmppV33, InterfaceVersion::SmppV33) => InterfaceVersion::SmppV33,
            
            // Mixed versions - negotiate to the lower common version
            (InterfaceVersion::SmppV50, InterfaceVersion::SmppV34) |
            (InterfaceVersion::SmppV34, InterfaceVersion::SmppV50) => InterfaceVersion::SmppV34,
            
            (InterfaceVersion::SmppV50, InterfaceVersion::SmppV33) |
            (InterfaceVersion::SmppV33, InterfaceVersion::SmppV50) => InterfaceVersion::SmppV33,
            
            (InterfaceVersion::SmppV34, InterfaceVersion::SmppV33) |
            (InterfaceVersion::SmppV33, InterfaceVersion::SmppV34) => InterfaceVersion::SmppV33,
        }
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
            Frame::BroadcastSm(_) => CommandId::BroadcastSm,
            Frame::BroadcastSmResp(_) => CommandId::BroadcastSmResp,
            Frame::QueryBroadcastSm(_) => CommandId::QueryBroadcastSm,
            Frame::QueryBroadcastSmResp(_) => CommandId::QueryBroadcastSmResp,
            Frame::CancelBroadcastSm(_) => CommandId::CancelBroadcastSm,
            Frame::CancelBroadcastSmResp(_) => CommandId::CancelBroadcastSmResp,
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
            Frame::BroadcastSm(pdu) => pdu.sequence_number,
            Frame::BroadcastSmResp(pdu) => pdu.sequence_number,
            Frame::QueryBroadcastSm(pdu) => pdu.sequence_number,
            Frame::QueryBroadcastSmResp(pdu) => pdu.sequence_number,
            Frame::CancelBroadcastSm(pdu) => pdu.sequence_number,
            Frame::CancelBroadcastSmResp(pdu) => pdu.sequence_number,
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
    fn registry_decode_unknown_pdu() {
        let registry = PduRegistry::new();

        // Use BindReceiver command_id - exists in CommandId enum but not registered in registry
        let unknown_command_id = 0x0000_0001u32; // CommandId::BindReceiver

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
    fn codec_error_to_command_status_mapping() {
        use crate::datatypes::CommandStatus;
        
        // Test field-specific error mapping
        let source_addr_error = CodecError::FieldValidation {
            field: "source_addr",
            reason: "Invalid format".to_string(),
        };
        assert_eq!(source_addr_error.to_command_status(), CommandStatus::InvalidSourceAddress);
        
        let destination_addr_error = CodecError::FieldValidation {
            field: "destination_addr", 
            reason: "Invalid format".to_string(),
        };
        assert_eq!(destination_addr_error.to_command_status(), CommandStatus::InvalidDestinationAddress);
        
        let system_id_error = CodecError::FieldValidation {
            field: "system_id",
            reason: "Too long".to_string(),
        };
        assert_eq!(system_id_error.to_command_status(), CommandStatus::InvalidSystemId);
        
        let password_error = CodecError::FieldValidation {
            field: "password",
            reason: "Invalid".to_string(),
        };
        assert_eq!(password_error.to_command_status(), CommandStatus::InvalidPassword);
        
        let short_message_error = CodecError::FieldValidation {
            field: "short_message",
            reason: "Too long".to_string(),
        };
        assert_eq!(short_message_error.to_command_status(), CommandStatus::InvalidMsgLength);
        
        let esm_class_error = CodecError::FieldValidation {
            field: "esm_class",
            reason: "Invalid bits".to_string(),
        };
        assert_eq!(esm_class_error.to_command_status(), CommandStatus::InvalidEsmClassFieldData);
        
        // Test TON/NPI specific errors
        let source_ton_error = CodecError::FieldValidation {
            field: "source_addr_ton",
            reason: "Invalid value".to_string(),
        };
        assert_eq!(source_ton_error.to_command_status(), CommandStatus::InvalidSourceAddressTon);
        
        let dest_npi_error = CodecError::FieldValidation {
            field: "dest_addr_npi",
            reason: "Invalid value".to_string(),
        };
        assert_eq!(dest_npi_error.to_command_status(), CommandStatus::InvalidDestinationAddressNpi);
        
        // Test TLV error mapping
        let tlv_length_error = CodecError::TlvError("Invalid length".to_string());
        assert_eq!(tlv_length_error.to_command_status(), CommandStatus::InvalidMsgLength);
        
        let tlv_unknown_error = CodecError::TlvError("Unknown TLV tag".to_string());
        assert_eq!(tlv_unknown_error.to_command_status(), CommandStatus::SystemError);
        
        // Test UTF-8 error mapping
        let invalid_utf8_bytes = vec![0xFF, 0xFE];
        let utf8_error = match String::from_utf8(invalid_utf8_bytes) {
            Err(e) => CodecError::Utf8Error {
                field: "short_message",
                source: e,
            },
            Ok(_) => panic!("Expected UTF-8 error"),
        };
        assert_eq!(utf8_error.to_command_status(), CommandStatus::InvalidMsgLength);
        
        // Test command ID errors
        let invalid_command_id = CodecError::InvalidCommandId(0x99999999);
        assert_eq!(invalid_command_id.to_command_status(), CommandStatus::InvalidCommandId);
        
        let invalid_pdu_length = CodecError::InvalidPduLength {
            length: 5,
            min: 16,
            max: 65536,
        };
        assert_eq!(invalid_pdu_length.to_command_status(), CommandStatus::InvalidCommandLength);
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
