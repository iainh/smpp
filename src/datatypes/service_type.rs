// ABOUTME: Strongly-typed SMPP service type with predefined variants and custom support
// ABOUTME: Provides compile-time validation for common SMS service types and extensibility

use crate::datatypes::fixed_string::{FixedString, FixedStringError};
use std::fmt;
use std::str;

/// A strongly-typed SMPP service type that enforces protocol-specific validation
/// Service types indicate the SMS Application service associated with the message
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceType {
    /// Default service type (empty string)
    Default,
    /// Cellular Messaging Teleservice (CMT)
    Cmt,
    /// Cellular Paging Teleservice (CPT)  
    Cpt,
    /// Voice Mail Notification
    Vmn,
    /// Voice Mail Retrieval
    Vma,
    /// Wireless Application Protocol (WAP)
    Wap,
    /// Wireless Email Notification (WEN)
    Wen,
    /// SMS Chat
    Chat,
    /// Custom service type with validation
    Custom(FixedString<6>), // 5 chars + null terminator max per SMPP spec
}

impl ServiceType {
    /// Creates a new ServiceType from a string, using predefined variants when possible
    pub fn new(service: &str) -> Result<Self, ServiceTypeError> {
        if service.is_empty() {
            return Ok(ServiceType::Default);
        }

        // Check for predefined service types (case-insensitive)
        match service.to_uppercase().as_str() {
            "CMT" => Ok(ServiceType::Cmt),
            "CPT" => Ok(ServiceType::Cpt),
            "VMN" => Ok(ServiceType::Vmn),
            "VMA" => Ok(ServiceType::Vma),
            "WAP" => Ok(ServiceType::Wap),
            "WEN" => Ok(ServiceType::Wen),
            "CHAT" => Ok(ServiceType::Chat),
            _ => {
                // Validate as custom service type
                if service.len() > 5 {
                    return Err(ServiceTypeError::TooLong {
                        max_len: 5,
                        actual_len: service.len(),
                    });
                }

                // Service types should be alphanumeric and uppercase
                if !service.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Err(ServiceTypeError::InvalidFormat {
                        reason: "Service type must contain only alphanumeric characters"
                            .to_string(),
                    });
                }

                let fixed_string = FixedString::from_str(service)
                    .map_err(|e| ServiceTypeError::FixedStringError(e))?;

                Ok(ServiceType::Custom(fixed_string))
            }
        }
    }

    /// Creates a default service type (empty)
    pub fn default() -> Self {
        ServiceType::Default
    }

    /// Creates a CMT (Cellular Messaging Teleservice) service type
    pub fn cmt() -> Self {
        ServiceType::Cmt
    }

    /// Creates a WAP (Wireless Application Protocol) service type
    pub fn wap() -> Self {
        ServiceType::Wap
    }

    /// Creates a voice mail notification service type
    pub fn voice_mail_notification() -> Self {
        ServiceType::Vmn
    }

    /// Creates a custom service type with validation
    pub fn custom(service: &str) -> Result<Self, ServiceTypeError> {
        if service.is_empty() {
            return Ok(ServiceType::Default);
        }

        Self::new(service)
    }

    /// Returns the service type as a string slice
    pub fn as_str(&self) -> &str {
        match self {
            ServiceType::Default => "",
            ServiceType::Cmt => "CMT",
            ServiceType::Cpt => "CPT",
            ServiceType::Vmn => "VMN",
            ServiceType::Vma => "VMA",
            ServiceType::Wap => "WAP",
            ServiceType::Wen => "WEN",
            ServiceType::Chat => "CHAT",
            ServiceType::Custom(fixed_string) => fixed_string.as_str().unwrap_or(""),
        }
    }

    /// Returns the service type as bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Returns the underlying fixed string for custom types, None for predefined types
    pub fn as_fixed_string(&self) -> Option<&FixedString<6>> {
        match self {
            ServiceType::Custom(fixed_string) => Some(fixed_string),
            _ => None,
        }
    }

    /// Returns the length of the service type string
    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    /// Returns true if this is the default (empty) service type
    pub fn is_empty(&self) -> bool {
        matches!(self, ServiceType::Default)
    }

    /// Returns true if this is a predefined service type
    pub fn is_predefined(&self) -> bool {
        !matches!(self, ServiceType::Custom(_))
    }

    /// Returns true if this is a custom service type
    pub fn is_custom(&self) -> bool {
        matches!(self, ServiceType::Custom(_))
    }

    /// Returns true if this service type supports concatenated messages
    pub fn supports_concatenation(&self) -> bool {
        match self {
            ServiceType::Default | ServiceType::Cmt | ServiceType::Chat => true,
            ServiceType::Wap => true,
            _ => false, // WAP, voice mail, etc. typically don't support concatenation
        }
    }

    /// Returns true if this service type is typically used for notifications
    pub fn is_notification_service(&self) -> bool {
        matches!(self, ServiceType::Vmn | ServiceType::Wen)
    }

    /// Creates a ServiceType from a parsed C-string, for frame parsing compatibility
    pub fn from_parsed_string(s: String) -> Result<Self, ServiceTypeError> {
        Self::new(&s)
    }
}

/// Errors that can occur when creating or validating service types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceTypeError {
    /// The service type string is too long
    TooLong { max_len: usize, actual_len: usize },
    /// The service type format is invalid
    InvalidFormat { reason: String },
    /// Error from underlying FixedString
    FixedStringError(FixedStringError),
}

impl fmt::Display for ServiceTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceTypeError::TooLong {
                max_len,
                actual_len,
            } => {
                write!(
                    f,
                    "Service type too long: {} chars (max {})",
                    actual_len, max_len
                )
            }
            ServiceTypeError::InvalidFormat { reason } => {
                write!(f, "Invalid service type format: {}", reason)
            }
            ServiceTypeError::FixedStringError(e) => {
                write!(f, "FixedString error: {}", e)
            }
        }
    }
}

impl std::error::Error for ServiceTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServiceTypeError::FixedStringError(e) => Some(e),
            _ => None,
        }
    }
}

// Default implementation
impl Default for ServiceType {
    fn default() -> Self {
        ServiceType::Default
    }
}

// Display implementation
impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl fmt::Debug for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceType::Default => write!(f, "ServiceType::Default"),
            ServiceType::Cmt => write!(f, "ServiceType::Cmt"),
            ServiceType::Cpt => write!(f, "ServiceType::Cpt"),
            ServiceType::Vmn => write!(f, "ServiceType::Vmn"),
            ServiceType::Vma => write!(f, "ServiceType::Vma"),
            ServiceType::Wap => write!(f, "ServiceType::Wap"),
            ServiceType::Wen => write!(f, "ServiceType::Wen"),
            ServiceType::Chat => write!(f, "ServiceType::Chat"),
            ServiceType::Custom(fs) => write!(f, "ServiceType::Custom(\"{}\")", fs),
        }
    }
}

// AsRef implementation for serialization
impl AsRef<[u8]> for ServiceType {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

// Comparison implementations
impl PartialEq<str> for ServiceType {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ServiceType {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for ServiceType {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

// From implementations for convenience
impl From<&str> for ServiceType {
    fn from(s: &str) -> Self {
        Self::new(s).expect("Invalid service type format")
    }
}

impl TryFrom<String> for ServiceType {
    type Error = ServiceTypeError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

// Conversion from FixedString for backward compatibility
impl From<FixedString<6>> for ServiceType {
    fn from(fixed_string: FixedString<6>) -> Self {
        let s = fixed_string.as_str().unwrap_or("");
        Self::new(s).unwrap_or(ServiceType::Default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_type_default() {
        let st = ServiceType::default();
        assert_eq!(st.as_str(), "");
        assert!(st.is_empty());
        assert!(!st.is_custom());
        assert!(st.is_predefined());
    }

    #[test]
    fn test_service_type_predefined() {
        let cmt = ServiceType::cmt();
        assert_eq!(cmt.as_str(), "CMT");
        assert!(!cmt.is_empty());
        assert!(!cmt.is_custom());
        assert!(cmt.is_predefined());
        assert!(cmt.supports_concatenation());

        let wap = ServiceType::wap();
        assert_eq!(wap.as_str(), "WAP");
        assert!(wap.supports_concatenation());

        let vmn = ServiceType::voice_mail_notification();
        assert_eq!(vmn.as_str(), "VMN");
        assert!(vmn.is_notification_service());
    }

    #[test]
    fn test_service_type_from_string() {
        let cmt = ServiceType::new("CMT").unwrap();
        assert_eq!(cmt, ServiceType::Cmt);

        let cmt_lower = ServiceType::new("cmt").unwrap();
        assert_eq!(cmt_lower, ServiceType::Cmt);

        let wap = ServiceType::new("WAP").unwrap();
        assert_eq!(wap, ServiceType::Wap);

        let empty = ServiceType::new("").unwrap();
        assert_eq!(empty, ServiceType::Default);
    }

    #[test]
    fn test_service_type_custom() {
        let custom = ServiceType::custom("TEST1").unwrap();
        assert_eq!(custom.as_str(), "TEST1");
        assert!(custom.is_custom());
        assert!(!custom.is_predefined());
        assert!(!custom.supports_concatenation());

        let custom2 = ServiceType::new("XYZ").unwrap();
        assert!(matches!(custom2, ServiceType::Custom(_)));
        assert_eq!(custom2.as_str(), "XYZ");
    }

    #[test]
    fn test_service_type_invalid_custom() {
        // Too long
        let result = ServiceType::custom("TOOLONG");
        assert!(matches!(result, Err(ServiceTypeError::TooLong { .. })));

        // Invalid characters
        let result = ServiceType::custom("TEST@");
        assert!(matches!(
            result,
            Err(ServiceTypeError::InvalidFormat { .. })
        ));
    }

    #[test]
    fn test_service_type_comparison() {
        let cmt = ServiceType::Cmt;
        assert_eq!(cmt, "CMT");
        assert_eq!(cmt, "CMT".to_string());

        let custom = ServiceType::custom("TEST").unwrap();
        assert_eq!(custom, "TEST");
        assert_ne!(custom, "test"); // Case sensitive for custom types
    }

    #[test]
    fn test_service_type_display() {
        let cmt = ServiceType::Cmt;
        assert_eq!(format!("{}", cmt), "CMT");

        let default = ServiceType::Default;
        assert_eq!(format!("{}", default), "");

        let custom = ServiceType::custom("ABC").unwrap();
        assert_eq!(format!("{}", custom), "ABC");
    }

    #[test]
    fn test_service_type_characteristics() {
        // Test concatenation support
        assert!(ServiceType::Default.supports_concatenation());
        assert!(ServiceType::Cmt.supports_concatenation());
        assert!(ServiceType::Wap.supports_concatenation());
        assert!(!ServiceType::Vmn.supports_concatenation());

        // Test notification services
        assert!(ServiceType::Vmn.is_notification_service());
        assert!(ServiceType::Wen.is_notification_service());
        assert!(!ServiceType::Cmt.is_notification_service());
        assert!(!ServiceType::Default.is_notification_service());
    }

    #[test]
    fn test_service_type_case_insensitive_predefined() {
        let variants = vec![
            ("cmt", ServiceType::Cmt),
            ("CMT", ServiceType::Cmt),
            ("CmT", ServiceType::Cmt),
            ("wap", ServiceType::Wap),
            ("WAP", ServiceType::Wap),
            ("vmn", ServiceType::Vmn),
            ("chat", ServiceType::Chat),
        ];

        for (input, expected) in variants {
            let st = ServiceType::new(input).unwrap();
            assert_eq!(st, expected, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_service_type_fixed_string_conversion() {
        let fixed = FixedString::<6>::from_str("TEST").unwrap();
        let st = ServiceType::from(fixed);
        assert!(matches!(st, ServiceType::Custom(_)));
        assert_eq!(st.as_str(), "TEST");
    }

    #[test]
    fn test_service_type_edge_cases() {
        // Maximum length custom service type
        let max_custom = ServiceType::custom("ABCDE").unwrap(); // 5 chars is max
        assert_eq!(max_custom.len(), 5);
        assert_eq!(max_custom.as_str(), "ABCDE");

        // Single character
        let single = ServiceType::custom("X").unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(single.as_str(), "X");
    }
}
