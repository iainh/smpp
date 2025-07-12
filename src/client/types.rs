// ABOUTME: Supporting types for SMPP client operations including credentials and message builders
// ABOUTME: Provides simplified interfaces for common SMPP operations with sensible defaults

use crate::datatypes::{DataCoding, NumericPlanIndicator, PriorityFlag, TypeOfNumber};

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
}

impl BindCredentials {
    /// Create new bind credentials for transmitter session
    pub fn transmitter(system_id: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            system_id: system_id.into(),
            password: password.into(),
            system_type: None,
            bind_type: BindType::Transmitter,
        }
    }

    /// Create new bind credentials for receiver session
    pub fn receiver(system_id: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            system_id: system_id.into(),
            password: password.into(),
            system_type: None,
            bind_type: BindType::Receiver,
        }
    }

    /// Create new bind credentials for transceiver session
    pub fn transceiver(system_id: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            system_id: system_id.into(),
            password: password.into(),
            system_type: None,
            bind_type: BindType::Transceiver,
        }
    }

    /// Set system type
    pub fn with_system_type(mut self, system_type: impl Into<String>) -> Self {
        self.system_type = Some(system_type.into());
        self
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
