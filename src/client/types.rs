// ABOUTME: Supporting types for SMPP client operations including credentials and message builders
// ABOUTME: Provides simplified interfaces for common SMPP operations with sensible defaults

use crate::datatypes::{DataCoding, NumericPlanIndicator, PriorityFlag, TypeOfNumber, InterfaceVersion};

/// SMPP bind operation credentials
///
/// Contains authentication information and bind type for establishing
/// SMPP sessions with the SMSC.
#[derive(Debug, Clone)]
pub struct BindCredentials {
    /// System identifier for authentication
    pub system_id: String,
    /// Password for authentication
    pub password: String,
    /// System type (optional, defaults to empty string)
    pub system_type: Option<String>,
    /// Type of bind operation to perform
    pub bind_type: BindType,
    /// SMPP interface version to use
    pub interface_version: InterfaceVersion,
}

impl BindCredentials {
    /// Create new bind credentials for transmitter session (defaults to SMPP v3.4)
    pub fn transmitter(system_id: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            system_id: system_id.into(),
            password: password.into(),
            system_type: None,
            bind_type: BindType::Transmitter,
            interface_version: InterfaceVersion::SmppV34,
        }
    }

    /// Create new bind credentials for receiver session (defaults to SMPP v3.4)
    pub fn receiver(system_id: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            system_id: system_id.into(),
            password: password.into(),
            system_type: None,
            bind_type: BindType::Receiver,
            interface_version: InterfaceVersion::SmppV34,
        }
    }

    /// Create new bind credentials for transceiver session (defaults to SMPP v3.4)
    pub fn transceiver(system_id: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            system_id: system_id.into(),
            password: password.into(),
            system_type: None,
            bind_type: BindType::Transceiver,
            interface_version: InterfaceVersion::SmppV34,
        }
    }

    /// Create new bind credentials for transmitter session with SMPP v5.0
    pub fn transmitter_v50(system_id: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            system_id: system_id.into(),
            password: password.into(),
            system_type: None,
            bind_type: BindType::Transmitter,
            interface_version: InterfaceVersion::SmppV50,
        }
    }

    /// Create new bind credentials for receiver session with SMPP v5.0
    pub fn receiver_v50(system_id: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            system_id: system_id.into(),
            password: password.into(),
            system_type: None,
            bind_type: BindType::Receiver,
            interface_version: InterfaceVersion::SmppV50,
        }
    }

    /// Create new bind credentials for transceiver session with SMPP v5.0
    pub fn transceiver_v50(system_id: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            system_id: system_id.into(),
            password: password.into(),
            system_type: None,
            bind_type: BindType::Transceiver,
            interface_version: InterfaceVersion::SmppV50,
        }
    }

    /// Set system type
    pub fn with_system_type(mut self, system_type: impl Into<String>) -> Self {
        self.system_type = Some(system_type.into());
        self
    }

    /// Set SMPP interface version
    pub fn with_version(mut self, interface_version: InterfaceVersion) -> Self {
        self.interface_version = interface_version;
        self
    }

    /// Check if this bind uses SMPP v5.0
    pub fn is_v50(&self) -> bool {
        self.interface_version == InterfaceVersion::SmppV50
    }
}

/// Type of SMPP bind operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindType {
    /// Bind as transmitter (can send submit_sm)
    Transmitter,
    /// Bind as receiver (can receive deliver_sm)
    Receiver,
    /// Bind as transceiver (both transmitter and receiver capabilities)
    Transceiver,
}

/// Simplified SMS message for easy client usage
///
/// Provides a high-level interface for SMS messages with sensible defaults,
/// hiding the complexity of the underlying SubmitSm PDU structure.
#[derive(Debug, Clone)]
pub struct SmsMessage {
    /// Destination phone number
    pub to: String,
    /// Source phone number
    pub from: String,
    /// Message text content
    pub text: String,
    /// Additional message options
    pub options: SmsOptions,
}

impl SmsMessage {
    /// Create a new SMS message with default options
    pub fn new(to: impl Into<String>, from: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            to: to.into(),
            from: from.into(),
            text: text.into(),
            options: SmsOptions::default(),
        }
    }

    /// Create a builder for constructing SMS messages
    pub fn builder() -> SmsMessageBuilder {
        SmsMessageBuilder::default()
    }
}

/// SMS message options with sensible defaults
#[derive(Debug, Clone)]
pub struct SmsOptions {
    /// Message priority level
    pub priority: PriorityFlag,
    /// Data coding scheme
    pub data_coding: DataCoding,
    /// Source address type of number
    pub source_ton: TypeOfNumber,
    /// Source address numbering plan indicator
    pub source_npi: NumericPlanIndicator,
    /// Destination address type of number
    pub dest_ton: TypeOfNumber,
    /// Destination address numbering plan indicator
    pub dest_npi: NumericPlanIndicator,
    /// Request delivery receipt (0 = no, 1 = yes)
    pub registered_delivery: u8,
}

impl Default for SmsOptions {
    fn default() -> Self {
        Self {
            priority: PriorityFlag::Level0,
            data_coding: DataCoding::default(),
            source_ton: TypeOfNumber::Unknown,
            source_npi: NumericPlanIndicator::Unknown,
            dest_ton: TypeOfNumber::Unknown,
            dest_npi: NumericPlanIndicator::Unknown,
            registered_delivery: 0,
        }
    }
}

/// Builder for constructing SMS messages with fluent API
#[derive(Debug, Default)]
pub struct SmsMessageBuilder {
    to: Option<String>,
    from: Option<String>,
    text: Option<String>,
    options: SmsOptions,
}

impl SmsMessageBuilder {
    /// Set destination phone number
    pub fn to(mut self, to: impl Into<String>) -> Self {
        self.to = Some(to.into());
        self
    }

    /// Set source phone number
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Set message text
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    /// Set message priority
    pub fn priority(mut self, priority: PriorityFlag) -> Self {
        self.options.priority = priority;
        self
    }

    /// Set data coding scheme
    pub fn data_coding(mut self, data_coding: DataCoding) -> Self {
        self.options.data_coding = data_coding;
        self
    }

    /// Request delivery receipt
    pub fn with_delivery_receipt(mut self) -> Self {
        self.options.registered_delivery = 1;
        self
    }

    /// Set source address numbering
    pub fn source_numbering(mut self, ton: TypeOfNumber, npi: NumericPlanIndicator) -> Self {
        self.options.source_ton = ton;
        self.options.source_npi = npi;
        self
    }

    /// Set destination address numbering
    pub fn dest_numbering(mut self, ton: TypeOfNumber, npi: NumericPlanIndicator) -> Self {
        self.options.dest_ton = ton;
        self.options.dest_npi = npi;
        self
    }

    /// Build the SMS message
    pub fn build(self) -> Result<SmsMessage, String> {
        let to = self.to.ok_or("Destination phone number is required")?;
        let from = self.from.ok_or("Source phone number is required")?;
        let text = self.text.ok_or("Message text is required")?;

        if text.len() > 254 {
            return Err("Message text too long (max 254 bytes for short_message)".to_string());
        }

        Ok(SmsMessage {
            to,
            from,
            text,
            options: self.options,
        })
    }
}

/// SMPP v5.0 broadcast message for client usage
///
/// Provides a high-level interface for broadcast messages with sensible defaults,
/// hiding the complexity of the underlying BroadcastSm PDU structure.
#[derive(Debug, Clone)]
pub struct BroadcastMessage {
    /// Source phone number
    pub from: String,
    /// Message ID for tracking
    pub message_id: String,
    /// Broadcast area identifier
    pub broadcast_area_identifier: Vec<u8>,
    /// Broadcast content type
    pub broadcast_content_type: u8,
    /// Number of repetitions
    pub broadcast_rep_num: u16,
    /// Frequency interval in seconds
    pub broadcast_frequency_interval: u32,
    /// Additional broadcast options
    pub options: BroadcastOptions,
}

impl BroadcastMessage {
    /// Create a new broadcast message with default options
    pub fn new(
        from: impl Into<String>,
        message_id: impl Into<String>,
        broadcast_area_identifier: Vec<u8>,
    ) -> Self {
        Self {
            from: from.into(),
            message_id: message_id.into(),
            broadcast_area_identifier,
            broadcast_content_type: 0,
            broadcast_rep_num: 1,
            broadcast_frequency_interval: 3600, // 1 hour default
            options: BroadcastOptions::default(),
        }
    }

    /// Create a builder for constructing broadcast messages
    pub fn builder() -> BroadcastMessageBuilder {
        BroadcastMessageBuilder::default()
    }
}

/// Broadcast message options with sensible defaults
#[derive(Debug, Clone)]
pub struct BroadcastOptions {
    /// Message priority level
    pub priority: PriorityFlag,
    /// Data coding scheme
    pub data_coding: DataCoding,
    /// Source address type of number
    pub source_ton: TypeOfNumber,
    /// Source address numbering plan indicator
    pub source_npi: NumericPlanIndicator,
}

impl Default for BroadcastOptions {
    fn default() -> Self {
        Self {
            priority: PriorityFlag::Level0,
            data_coding: DataCoding::default(),
            source_ton: TypeOfNumber::Unknown,
            source_npi: NumericPlanIndicator::Unknown,
        }
    }
}

/// Builder for constructing broadcast messages with fluent API
#[derive(Debug, Default)]
pub struct BroadcastMessageBuilder {
    from: Option<String>,
    message_id: Option<String>,
    broadcast_area_identifier: Option<Vec<u8>>,
    broadcast_content_type: u8,
    broadcast_rep_num: u16,
    broadcast_frequency_interval: u32,
    options: BroadcastOptions,
}

impl BroadcastMessageBuilder {
    /// Set source phone number
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Set message ID for tracking
    pub fn message_id(mut self, message_id: impl Into<String>) -> Self {
        self.message_id = Some(message_id.into());
        self
    }

    /// Set broadcast area identifier
    pub fn area_identifier(mut self, identifier: Vec<u8>) -> Self {
        self.broadcast_area_identifier = Some(identifier);
        self
    }

    /// Set broadcast content type
    pub fn content_type(mut self, content_type: u8) -> Self {
        self.broadcast_content_type = content_type;
        self
    }

    /// Set number of repetitions
    pub fn repetitions(mut self, repetitions: u16) -> Self {
        self.broadcast_rep_num = repetitions;
        self
    }

    /// Set frequency interval in seconds
    pub fn frequency_interval(mut self, interval: u32) -> Self {
        self.broadcast_frequency_interval = interval;
        self
    }

    /// Set message priority
    pub fn priority(mut self, priority: PriorityFlag) -> Self {
        self.options.priority = priority;
        self
    }

    /// Set data coding scheme
    pub fn data_coding(mut self, data_coding: DataCoding) -> Self {
        self.options.data_coding = data_coding;
        self
    }

    /// Set source address numbering
    pub fn source_numbering(mut self, ton: TypeOfNumber, npi: NumericPlanIndicator) -> Self {
        self.options.source_ton = ton;
        self.options.source_npi = npi;
        self
    }

    /// Build the broadcast message
    pub fn build(self) -> Result<BroadcastMessage, String> {
        let from = self.from.ok_or("Source phone number is required")?;
        let message_id = self.message_id.ok_or("Message ID is required")?;
        let broadcast_area_identifier = self
            .broadcast_area_identifier
            .ok_or("Broadcast area identifier is required")?;

        if broadcast_area_identifier.is_empty() {
            return Err("Broadcast area identifier cannot be empty".to_string());
        }

        if self.broadcast_rep_num == 0 {
            return Err("Broadcast repetition number must be greater than 0".to_string());
        }

        Ok(BroadcastMessage {
            from,
            message_id,
            broadcast_area_identifier,
            broadcast_content_type: self.broadcast_content_type,
            broadcast_rep_num: self.broadcast_rep_num,
            broadcast_frequency_interval: self.broadcast_frequency_interval,
            options: self.options,
        })
    }
}
