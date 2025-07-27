// ABOUTME: Implements SMPP v3.4 alert_notification PDU for SMSC event notifications
// ABOUTME: Provides notification functionality per specification Section 4.12

use crate::datatypes::{
    AddressError, CommandId, CommandStatus, NumericPlanIndicator, SourceAddr, TypeOfNumber,
};
use bytes::{BufMut, BytesMut};
use std::io::Cursor;
use thiserror::Error;

// Import codec traits
use crate::codec::{
    CodecError, Decodable, Encodable, PduHeader, decode_cstring, decode_u8, encode_cstring,
    encode_u8,
};

/// Validation errors for AlertNotification PDU
#[derive(Debug, Error)]
pub enum AlertNotificationValidationError {
    #[error("Source address error: {0}")]
    SourceAddr(AddressError),
    #[error("ESME address error: {0}")]
    EsmeAddr(AddressError),
}

/// SMPP v3.4 alert_notification PDU (Section 4.12.1)
///
/// The alert_notification PDU is sent by the SMSC to an ESME to notify it of
/// the availability of a mobile subscriber for message delivery. This PDU is
/// typically used when:
/// - A mobile subscriber becomes available after being unreachable
/// - The SMSC wants to notify the ESME that queued messages can now be delivered
/// - A subscriber's status changes from unavailable to available
///
/// ## Key Features
/// - Notification-only PDU (no response PDU)
/// - Indicates subscriber availability for message delivery
/// - Provides source and ESME address information
/// - Used for efficient message queue management
///
/// ## Mandatory Parameters
/// - source_addr_ton: Type of Number of the subscriber
/// - source_addr_npi: Numbering Plan Indicator of the subscriber
/// - source_addr: Address of the available subscriber
/// - esme_addr_ton: Type of Number for ESME address
/// - esme_addr_npi: Numbering Plan Indicator for ESME address
/// - esme_addr: Address of the ESME to be notified
///
/// ## Usage Scenarios
/// 1. **Subscriber Availability**: Mobile device comes back online
/// 2. **Network Recovery**: Network connectivity restored to subscriber
/// 3. **Roaming Updates**: Subscriber enters coverage area
/// 4. **Queue Management**: SMSC ready to deliver pending messages
///
/// ## References
/// - SMPP v3.4 Specification Section 4.12.1
#[derive(Clone, Debug, PartialEq)]
pub struct AlertNotification {
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Mandatory parameters
    /// Type of Number of the subscriber that is now available.
    /// Indicates the addressing scheme used for the source address.
    pub source_addr_ton: TypeOfNumber,

    /// Numbering Plan Indicator of the subscriber that is now available.
    /// Specifies the numbering plan for the source address.
    pub source_addr_npi: NumericPlanIndicator,

    /// Address of the subscriber that is now available for message delivery.
    /// This is typically a mobile phone number or subscriber identifier.
    pub source_addr: SourceAddr,

    /// Type of Number for the ESME address.
    /// Indicates the addressing scheme used for the ESME address.
    pub esme_addr_ton: TypeOfNumber,

    /// Numbering Plan Indicator for the ESME address.
    /// Specifies the numbering plan for the ESME address.
    pub esme_addr_npi: NumericPlanIndicator,

    /// Address of the ESME that should be notified.
    /// This identifies which ESME should be informed of the subscriber availability.
    pub esme_addr: SourceAddr, // Reusing SourceAddr type for ESME address
}

impl AlertNotification {
    /// Create a new AlertNotification PDU
    pub fn new(
        sequence_number: u32,
        source_addr_ton: TypeOfNumber,
        source_addr_npi: NumericPlanIndicator,
        source_addr: SourceAddr,
        esme_addr_ton: TypeOfNumber,
        esme_addr_npi: NumericPlanIndicator,
        esme_addr: SourceAddr,
    ) -> Result<Self, AlertNotificationValidationError> {
        let pdu = AlertNotification {
            command_status: CommandStatus::Ok, // Always 0 for notifications
            sequence_number,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            esme_addr_ton,
            esme_addr_npi,
            esme_addr,
        };

        // Validate the PDU
        pdu.validate()?;
        Ok(pdu)
    }

    /// Create an AlertNotification for a mobile subscriber becoming available
    pub fn subscriber_available(
        sequence_number: u32,
        subscriber_number: &str,
        subscriber_ton: TypeOfNumber,
        subscriber_npi: NumericPlanIndicator,
        esme_address: &str,
        esme_ton: TypeOfNumber,
        esme_npi: NumericPlanIndicator,
    ) -> Result<Self, AlertNotificationValidationError> {
        let source_addr = SourceAddr::new(subscriber_number, subscriber_ton)
            .map_err(AlertNotificationValidationError::SourceAddr)?;
        let esme_addr = SourceAddr::new(esme_address, esme_ton)
            .map_err(AlertNotificationValidationError::EsmeAddr)?;

        Self::new(
            sequence_number,
            subscriber_ton,
            subscriber_npi,
            source_addr,
            esme_ton,
            esme_npi,
            esme_addr,
        )
    }

    /// Create an AlertNotification for international mobile subscriber
    pub fn international_subscriber_available(
        sequence_number: u32,
        subscriber_number: &str,
        esme_address: &str,
    ) -> Result<Self, AlertNotificationValidationError> {
        Self::subscriber_available(
            sequence_number,
            subscriber_number,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            esme_address,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
        )
    }

    /// Get the subscriber address that is now available
    pub fn get_subscriber_address(&self) -> &SourceAddr {
        &self.source_addr
    }

    /// Get the ESME address to be notified
    pub fn get_esme_address(&self) -> &SourceAddr {
        &self.esme_addr
    }

    /// Check if this notification is for an international subscriber
    pub fn is_international_subscriber(&self) -> bool {
        self.source_addr_ton == TypeOfNumber::International
    }

    /// Check if this notification is for an international ESME
    pub fn is_international_esme(&self) -> bool {
        self.esme_addr_ton == TypeOfNumber::International
    }

    /// Get the subscriber number as a string (if available)
    pub fn get_subscriber_number(&self) -> Option<&str> {
        self.source_addr.as_str().ok()
    }

    /// Get the ESME address as a string (if available)
    pub fn get_esme_address_string(&self) -> Option<&str> {
        self.esme_addr.as_str().ok()
    }

    /// Validate the AlertNotification PDU
    fn validate(&self) -> Result<(), AlertNotificationValidationError> {
        // source_addr validation is handled by SourceAddr type
        // esme_addr validation is handled by SourceAddr type
        Ok(())
    }
}

impl Encodable for AlertNotification {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // PDU Header (will be filled by codec)
        buf.put_u32(0); // command_length (placeholder)
        buf.put_u32(CommandId::AlertNotification as u32);
        buf.put_u32(self.command_status as u32);
        buf.put_u32(self.sequence_number);

        // Mandatory parameters
        // source_addr_ton (1 octet)
        encode_u8(buf, self.source_addr_ton as u8);

        // source_addr_npi (1 octet)
        encode_u8(buf, self.source_addr_npi as u8);

        // source_addr (21 octets, null-terminated with padding)
        encode_cstring(buf, self.source_addr.as_str().ok().unwrap_or(""), 21);

        // esme_addr_ton (1 octet)
        encode_u8(buf, self.esme_addr_ton as u8);

        // esme_addr_npi (1 octet)
        encode_u8(buf, self.esme_addr_npi as u8);

        // esme_addr (21 octets, null-terminated with padding)
        encode_cstring(buf, self.esme_addr.as_str().ok().unwrap_or(""), 21);

        Ok(())
    }

    fn encoded_size(&self) -> usize {
        16 + 1 + 1 + 21 + 1 + 1 + 21 // header + fixed fields
    }
}

impl Decodable for AlertNotification {
    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::validate_header(&header)?;

        // Decode mandatory parameters
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

        let esme_addr_ton =
            TypeOfNumber::try_from(decode_u8(buf)?).map_err(|_| CodecError::FieldValidation {
                field: "esme_addr_ton",
                reason: "Invalid TypeOfNumber value".to_string(),
            })?;

        let esme_addr_npi = NumericPlanIndicator::try_from(decode_u8(buf)?).map_err(|_| {
            CodecError::FieldValidation {
                field: "esme_addr_npi",
                reason: "Invalid NumericPlanIndicator value".to_string(),
            }
        })?;

        let esme_addr_str = decode_cstring(buf, 21, "esme_addr")?;
        let esme_addr = SourceAddr::new(&esme_addr_str, esme_addr_ton).map_err(|e| {
            CodecError::FieldValidation {
                field: "esme_addr",
                reason: format!("{e}"),
            }
        })?;

        Ok(AlertNotification {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
            source_addr_ton,
            source_addr_npi,
            source_addr,
            esme_addr_ton,
            esme_addr_npi,
            esme_addr,
        })
    }

    fn command_id() -> CommandId {
        CommandId::AlertNotification
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datatypes::{NumericPlanIndicator, TypeOfNumber};

    #[test]
    fn test_alert_notification_creation() {
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let esme_addr = SourceAddr::new("ESME001", TypeOfNumber::Alphanumeric).unwrap();

        let alert_notification = AlertNotification::new(
            123,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::Alphanumeric,
            NumericPlanIndicator::Unknown,
            esme_addr,
        )
        .unwrap();

        assert_eq!(alert_notification.sequence_number, 123);
        assert_eq!(alert_notification.command_status, CommandStatus::Ok);
        assert_eq!(alert_notification.source_addr_ton, TypeOfNumber::International);
        assert_eq!(alert_notification.source_addr_npi, NumericPlanIndicator::Isdn);
        assert_eq!(alert_notification.source_addr.as_str().ok().unwrap(), "1234567890");
        assert_eq!(alert_notification.esme_addr_ton, TypeOfNumber::Alphanumeric);
        assert_eq!(alert_notification.esme_addr_npi, NumericPlanIndicator::Unknown);
        assert_eq!(alert_notification.esme_addr.as_str().ok().unwrap(), "ESME001");
    }

    #[test]
    fn test_alert_notification_subscriber_available() {
        let alert_notification = AlertNotification::subscriber_available(
            456,
            "+1234567890",
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            "SMSGATEWAY",
            TypeOfNumber::Alphanumeric,
            NumericPlanIndicator::Unknown,
        )
        .unwrap();

        assert_eq!(alert_notification.sequence_number, 456);
        assert_eq!(alert_notification.source_addr_ton, TypeOfNumber::International);
        assert_eq!(alert_notification.get_subscriber_number().unwrap(), "+1234567890");
        assert_eq!(alert_notification.get_esme_address_string().unwrap(), "SMSGATEWAY");
        assert!(alert_notification.is_international_subscriber());
    }

    #[test]
    fn test_alert_notification_international_subscriber() {
        let alert_notification = AlertNotification::international_subscriber_available(
            789,
            "+1234567890",
            "+1987654321",
        )
        .unwrap();

        assert_eq!(alert_notification.sequence_number, 789);
        assert_eq!(alert_notification.source_addr_ton, TypeOfNumber::International);
        assert_eq!(alert_notification.source_addr_npi, NumericPlanIndicator::Isdn);
        assert_eq!(alert_notification.esme_addr_ton, TypeOfNumber::International);
        assert_eq!(alert_notification.esme_addr_npi, NumericPlanIndicator::Isdn);
        assert!(alert_notification.is_international_subscriber());
        assert!(alert_notification.is_international_esme());
    }

    #[test]
    fn test_alert_notification_encoding_decoding() {
        let source_addr = SourceAddr::new("1234567890", TypeOfNumber::International).unwrap();
        let esme_addr = SourceAddr::new("ESMETEST", TypeOfNumber::Alphanumeric).unwrap();

        let original = AlertNotification::new(
            999,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::Alphanumeric,
            NumericPlanIndicator::Unknown,
            esme_addr,
        )
        .unwrap();

        // Test encoding
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Test decoding
        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::AlertNotification,
            command_status: CommandStatus::Ok,
            sequence_number: 999,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = AlertNotification::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_alert_notification_helper_methods() {
        let alert_notification = AlertNotification::international_subscriber_available(
            100,
            "+1234567890",
            "+1555666777",
        )
        .unwrap();

        // Test getter methods
        assert_eq!(alert_notification.get_subscriber_address().as_str().ok().unwrap(), "+1234567890");
        assert_eq!(alert_notification.get_esme_address().as_str().ok().unwrap(), "+1555666777");
        assert_eq!(alert_notification.get_subscriber_number().unwrap(), "+1234567890");
        assert_eq!(alert_notification.get_esme_address_string().unwrap(), "+1555666777");

        // Test type checking methods
        assert!(alert_notification.is_international_subscriber());
        assert!(alert_notification.is_international_esme());
    }

    #[test]
    fn test_alert_notification_national_subscriber() {
        let source_addr = SourceAddr::new("12345", TypeOfNumber::National).unwrap();
        let esme_addr = SourceAddr::new("67890", TypeOfNumber::National).unwrap();

        let alert_notification = AlertNotification::new(
            200,
            TypeOfNumber::National,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::National,
            NumericPlanIndicator::Isdn,
            esme_addr,
        )
        .unwrap();

        assert!(!alert_notification.is_international_subscriber());
        assert!(!alert_notification.is_international_esme());
        assert_eq!(alert_notification.source_addr_ton, TypeOfNumber::National);
        assert_eq!(alert_notification.esme_addr_ton, TypeOfNumber::National);
    }

    #[test]
    fn test_alert_notification_mixed_addressing() {
        let source_addr = SourceAddr::new("+1234567890", TypeOfNumber::International).unwrap();
        let esme_addr = SourceAddr::new("SMSHUB", TypeOfNumber::Alphanumeric).unwrap();

        let alert_notification = AlertNotification::new(
            300,
            TypeOfNumber::International,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::Alphanumeric,
            NumericPlanIndicator::Unknown,
            esme_addr,
        )
        .unwrap();

        // Test mixed addressing - international subscriber, alphanumeric ESME
        assert!(alert_notification.is_international_subscriber());
        assert!(!alert_notification.is_international_esme());
        assert_eq!(alert_notification.esme_addr_ton, TypeOfNumber::Alphanumeric);

        // Test encoding/decoding preserves mixed addressing
        let mut buf = BytesMut::new();
        alert_notification.encode(&mut buf).unwrap();

        let header = PduHeader {
            command_length: buf.len() as u32,
            command_id: CommandId::AlertNotification,
            command_status: CommandStatus::Ok,
            sequence_number: 300,
        };

        let mut cursor = Cursor::new(&buf[16..]); // Skip header
        let decoded = AlertNotification::decode(header, &mut cursor).unwrap();

        assert_eq!(alert_notification, decoded);
    }

    #[test]
    fn test_alert_notification_encoded_size() {
        let source_addr = SourceAddr::new("123", TypeOfNumber::National).unwrap();
        let esme_addr = SourceAddr::new("ESME", TypeOfNumber::Alphanumeric).unwrap();

        let alert_notification = AlertNotification::new(
            400,
            TypeOfNumber::National,
            NumericPlanIndicator::Isdn,
            source_addr,
            TypeOfNumber::Alphanumeric,
            NumericPlanIndicator::Unknown,
            esme_addr,
        )
        .unwrap();

        // Encoded size should be fixed: header (16) + ton (1) + npi (1) + addr (21) + ton (1) + npi (1) + addr (21) = 62
        assert_eq!(alert_notification.encoded_size(), 62);

        // Test actual encoding produces the expected size
        let mut buf = BytesMut::new();
        alert_notification.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 62);
    }
}