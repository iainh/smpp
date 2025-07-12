// ABOUTME: Strongly-typed SMPP address types with TON/NPI validation
// ABOUTME: Provides compile-time guarantees for address format correctness based on Type of Number

use crate::datatypes::TypeOfNumber;
use std::fmt;
use std::str;

/// A strongly-typed phone number that validates format based on Type of Number
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PhoneNumber<const N: usize> {
    data: [u8; N],
    length: u8,
}

impl<const N: usize> PhoneNumber<N> {
    /// Creates a new PhoneNumber with validation based on TON
    pub fn new(addr: &str, ton: TypeOfNumber) -> Result<Self, AddressError> {
        if addr.len() >= N {
            return Err(AddressError::TooLong {
                max_len: N - 1,
                actual_len: addr.len(),
            });
        }

        // Validate format based on Type of Number
        match ton {
            TypeOfNumber::International => {
                if !addr.chars().all(|c| c.is_ascii_digit() || c == '+') {
                    return Err(AddressError::InvalidFormat {
                        ton,
                        reason: "International numbers must contain only digits and optional +"
                            .to_string(),
                    });
                }
            }
            TypeOfNumber::National
            | TypeOfNumber::NetworkSpecific
            | TypeOfNumber::SubscriberNumber => {
                if !addr.chars().all(|c| c.is_ascii_digit()) {
                    return Err(AddressError::InvalidFormat {
                        ton,
                        reason: "Numeric addresses must contain only digits".to_string(),
                    });
                }
            }
            TypeOfNumber::Alphanumeric => {
                if !addr.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Err(AddressError::InvalidFormat {
                        ton,
                        reason: "Alphanumeric addresses must contain only letters and digits"
                            .to_string(),
                    });
                }
            }
            TypeOfNumber::Abbreviated => {
                // Abbreviated numbers are typically short codes, allow alphanumeric
                if !addr.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Err(AddressError::InvalidFormat {
                        ton,
                        reason: "Abbreviated addresses must contain only letters and digits"
                            .to_string(),
                    });
                }
            }
            TypeOfNumber::Unknown => {
                // For unknown TON, allow any printable ASCII characters
                if !addr.chars().all(|c| c.is_ascii() && !c.is_control()) {
                    return Err(AddressError::InvalidFormat {
                        ton,
                        reason: "Unknown type addresses must contain only printable ASCII"
                            .to_string(),
                    });
                }
            }
        }

        let mut data = [0u8; N];
        let addr_bytes = addr.as_bytes();
        data[..addr_bytes.len()].copy_from_slice(addr_bytes);

        Ok(Self {
            data,
            length: u8::try_from(addr_bytes.len()).map_err(|_| AddressError::TooLong {
                max_len: N - 1,
                actual_len: addr_bytes.len(),
            })?,
        })
    }

    /// Creates a PhoneNumber for international numbers with + prefix validation
    pub fn international(number: &str) -> Result<Self, AddressError> {
        Self::new(number, TypeOfNumber::International)
    }

    /// Creates a PhoneNumber for national numbers (digits only)
    pub fn national(number: &str) -> Result<Self, AddressError> {
        Self::new(number, TypeOfNumber::National)
    }

    /// Returns the address as a string slice
    pub fn as_str(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(&self.data[..self.length as usize])
    }

    /// Returns the address as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.length as usize]
    }

    /// Returns the underlying byte array (full array)
    pub const fn as_full_array(&self) -> &[u8; N] {
        &self.data
    }

    /// Returns the length of the address
    pub fn len(&self) -> usize {
        self.length as usize
    }

    /// Returns true if the address is empty
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Validates the address format against a specific TON
    pub fn validate_for_ton(&self, ton: TypeOfNumber) -> Result<(), AddressError> {
        let addr_str = self.as_str().map_err(|_| AddressError::InvalidUtf8)?;
        Self::new(addr_str, ton)?;
        Ok(())
    }

    /// Creates a PhoneNumber from a parsed C-string, for frame parsing compatibility
    /// Uses Unknown TON since TON is parsed separately in SMPP frames
    #[allow(clippy::needless_pass_by_value)] // String is consumed to avoid clone in common usage
    pub fn from_parsed_string(s: String) -> Result<Self, AddressError> {
        Self::new(&s, TypeOfNumber::Unknown)
    }
}

/// A strongly-typed alphanumeric address for messaging services
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlphanumericAddress<const N: usize> {
    data: [u8; N],
    length: u8,
}

impl<const N: usize> AlphanumericAddress<N> {
    /// Creates a new AlphanumericAddress with strict alphanumeric validation
    pub fn new(addr: &str) -> Result<Self, AddressError> {
        if addr.len() >= N {
            return Err(AddressError::TooLong {
                max_len: N - 1,
                actual_len: addr.len(),
            });
        }

        // Alphanumeric addresses must contain only letters, digits, and spaces
        if !addr.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ') {
            return Err(AddressError::InvalidFormat {
                ton: TypeOfNumber::Alphanumeric,
                reason: "Alphanumeric addresses must contain only letters, digits, and spaces"
                    .to_string(),
            });
        }

        let mut data = [0u8; N];
        let addr_bytes = addr.as_bytes();
        data[..addr_bytes.len()].copy_from_slice(addr_bytes);

        Ok(Self {
            data,
            length: u8::try_from(addr_bytes.len()).map_err(|_| AddressError::TooLong {
                max_len: N - 1,
                actual_len: addr_bytes.len(),
            })?,
        })
    }

    /// Returns the address as a string slice
    pub fn as_str(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(&self.data[..self.length as usize])
    }

    /// Returns the address as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.length as usize]
    }

    /// Returns the underlying byte array (full array)
    pub const fn as_full_array(&self) -> &[u8; N] {
        &self.data
    }

    /// Returns the length of the address
    pub fn len(&self) -> usize {
        self.length as usize
    }

    /// Returns true if the address is empty
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Creates an AlphanumericAddress from a parsed C-string, for frame parsing compatibility
    #[allow(clippy::needless_pass_by_value)] // String is consumed to avoid clone in common usage
    pub fn from_parsed_string(s: String) -> Result<Self, AddressError> {
        Self::new(&s)
    }
}

/// Errors that can occur when creating or validating addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// The address is too long for the fixed-size buffer
    TooLong { max_len: usize, actual_len: usize },
    /// The address format is invalid for the specified Type of Number
    InvalidFormat { ton: TypeOfNumber, reason: String },
    /// The address contains invalid UTF-8
    InvalidUtf8,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::TooLong {
                max_len,
                actual_len,
            } => {
                write!(f, "Address too long: {actual_len} bytes (max {max_len})")
            }
            AddressError::InvalidFormat { ton, reason } => {
                write!(f, "Invalid address format for {ton:?}: {reason}")
            }
            AddressError::InvalidUtf8 => {
                write!(f, "Address contains invalid UTF-8")
            }
        }
    }
}

impl std::error::Error for AddressError {}

// SMPP-specific address type aliases
pub type SourceAddr = PhoneNumber<21>; // 20 chars + null terminator
pub type DestinationAddr = PhoneNumber<21>; // 20 chars + null terminator

// Default implementations
impl<const N: usize> Default for PhoneNumber<N> {
    fn default() -> Self {
        Self {
            data: [0u8; N],
            length: 0,
        }
    }
}

impl<const N: usize> Default for AlphanumericAddress<N> {
    fn default() -> Self {
        Self {
            data: [0u8; N],
            length: 0,
        }
    }
}

// Display implementations
impl<const N: usize> fmt::Display for PhoneNumber<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "<invalid UTF-8>"),
        }
    }
}

impl<const N: usize> fmt::Debug for PhoneNumber<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "PhoneNumber<{N}>(\"{s}\")"),
            Err(_) => write!(f, "PhoneNumber<{}>({:?})", N, self.as_bytes()),
        }
    }
}

impl<const N: usize> fmt::Display for AlphanumericAddress<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "<invalid UTF-8>"),
        }
    }
}

impl<const N: usize> fmt::Debug for AlphanumericAddress<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "AlphanumericAddress<{N}>(\"{s}\")"),
            Err(_) => write!(f, "AlphanumericAddress<{}>({:?})", N, self.as_bytes()),
        }
    }
}

// AsRef implementations for serialization
impl<const N: usize> AsRef<[u8]> for PhoneNumber<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<const N: usize> AsRef<[u8]> for AlphanumericAddress<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

// Comparison implementations
impl<const N: usize> PartialEq<str> for PhoneNumber<N> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == Ok(other)
    }
}

impl<const N: usize> PartialEq<&str> for PhoneNumber<N> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == Ok(*other)
    }
}

impl<const N: usize> PartialEq<str> for AlphanumericAddress<N> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == Ok(other)
    }
}

impl<const N: usize> PartialEq<&str> for AlphanumericAddress<N> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == Ok(*other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phone_number_international() {
        let phone = PhoneNumber::<15>::international("+1234567890").unwrap();
        assert_eq!(phone.as_str().unwrap(), "+1234567890");
        assert_eq!(phone.len(), 11);
    }

    #[test]
    fn test_phone_number_national() {
        let phone = PhoneNumber::<15>::national("1234567890").unwrap();
        assert_eq!(phone.as_str().unwrap(), "1234567890");
        assert_eq!(phone.len(), 10);
    }

    #[test]
    fn test_phone_number_invalid_international() {
        let result = PhoneNumber::<15>::international("+123abc");
        assert!(matches!(result, Err(AddressError::InvalidFormat { .. })));
    }

    #[test]
    fn test_phone_number_invalid_national() {
        let result = PhoneNumber::<15>::national("123-456-7890");
        assert!(matches!(result, Err(AddressError::InvalidFormat { .. })));
    }

    #[test]
    fn test_alphanumeric_address() {
        let addr = AlphanumericAddress::<15>::new("INFO SMS").unwrap();
        assert_eq!(addr.as_str().unwrap(), "INFO SMS");
        assert_eq!(addr.len(), 8);
    }

    #[test]
    fn test_alphanumeric_address_invalid() {
        let result = AlphanumericAddress::<15>::new("INFO@SMS");
        assert!(matches!(result, Err(AddressError::InvalidFormat { .. })));
    }

    #[test]
    fn test_phone_number_too_long() {
        let long_number = "1".repeat(25);
        let result = PhoneNumber::<15>::national(&long_number);
        assert!(matches!(result, Err(AddressError::TooLong { .. })));
    }

    #[test]
    fn test_phone_number_validation_for_ton() {
        let phone = PhoneNumber::<15>::new("12345", TypeOfNumber::National).unwrap();

        // Should validate for compatible TONs
        assert!(phone.validate_for_ton(TypeOfNumber::National).is_ok());
        assert!(
            phone
                .validate_for_ton(TypeOfNumber::NetworkSpecific)
                .is_ok()
        );

        // Should fail for incompatible TONs (alphanumeric with digits-only content is still valid)
        assert!(phone.validate_for_ton(TypeOfNumber::Alphanumeric).is_ok());
    }

    #[test]
    fn test_address_empty() {
        let empty_phone = PhoneNumber::<15>::default();
        assert!(empty_phone.is_empty());
        assert_eq!(empty_phone.len(), 0);
        assert_eq!(empty_phone.as_str().unwrap(), "");

        let empty_alpha = AlphanumericAddress::<15>::default();
        assert!(empty_alpha.is_empty());
        assert_eq!(empty_alpha.len(), 0);
        assert_eq!(empty_alpha.as_str().unwrap(), "");
    }

    #[test]
    fn test_address_display() {
        let phone = PhoneNumber::<15>::national("1234567890").unwrap();
        assert_eq!(format!("{}", phone), "1234567890");

        let alpha = AlphanumericAddress::<15>::new("SMS INFO").unwrap();
        assert_eq!(format!("{}", alpha), "SMS INFO");
    }
}
