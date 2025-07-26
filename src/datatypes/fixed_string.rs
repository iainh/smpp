// ABOUTME: Fixed-size string types for SMPP protocol fields to eliminate heap allocations
// ABOUTME: Provides ergonomic newtype wrappers around byte arrays with Display/Debug traits

use std::fmt;
use std::str;
use std::str::FromStr;

/// A fixed-size null-terminated string with compile-time size validation
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixedString<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> FixedString<N> {
    /// Creates a new FixedString from a byte slice, padding with nulls if needed
    pub fn new(s: &[u8]) -> Result<Self, FixedStringError> {
        if s.len() >= N {
            return Err(FixedStringError::TooLong {
                max_len: N - 1,
                actual_len: s.len(),
            });
        }

        let mut data = [0u8; N];
        data[..s.len()].copy_from_slice(s);
        Ok(Self { data })
    }

    /// Creates a new FixedString from raw bytes without validation (unsafe)
    /// The caller must ensure the data is valid and properly null-terminated
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - The data array contains valid UTF-8 bytes (up to the first null byte)
    /// - The data is properly null-terminated or contains only valid content
    /// - The length semantics are preserved (content before first null byte)
    pub const unsafe fn from_raw_bytes(data: [u8; N]) -> Self {
        Self { data }
    }

    /// Returns the underlying byte array
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.data
    }

    /// Returns the string content as a byte slice, excluding null padding
    pub fn as_str_bytes(&self) -> &[u8] {
        // Find the first null byte, or use full length if no null found
        let len = self.data.iter().position(|&b| b == 0).unwrap_or(N);
        &self.data[..len]
    }

    /// Returns the string content as a str, excluding null padding
    pub fn as_str(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(self.as_str_bytes())
    }

    /// Returns the length of the string content (excluding null padding)
    pub fn len(&self) -> usize {
        self.as_str_bytes().len()
    }

    /// Returns true if the string is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears the string, setting all bytes to zero
    pub fn clear(&mut self) {
        self.data.fill(0);
    }

    /// Returns true if the string contains the given character
    pub fn contains(&self, ch: char) -> bool {
        self.as_str().is_ok_and(|s| s.contains(ch))
    }
}

impl<const N: usize> fmt::Display for FixedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "<invalid UTF-8>"),
        }
    }
}

impl<const N: usize> fmt::Debug for FixedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "FixedString<{N}>(\"{s}\")"),
            Err(_) => write!(f, "FixedString<{}>({:?})", N, self.as_str_bytes()),
        }
    }
}

impl<const N: usize> Default for FixedString<N> {
    fn default() -> Self {
        Self { data: [0u8; N] }
    }
}

impl<const N: usize> From<&str> for FixedString<N> {
    fn from(s: &str) -> Self {
        s.parse().expect("String too long for FixedString")
    }
}

impl<const N: usize> TryFrom<String> for FixedString<N> {
    type Error = FixedStringError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl<const N: usize> FromStr for FixedString<N> {
    type Err = FixedStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.as_bytes())
    }
}

impl<const N: usize> AsRef<[u8]> for FixedString<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_str_bytes()
    }
}

impl<const N: usize> PartialEq<str> for FixedString<N> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == Ok(other)
    }
}

impl<const N: usize> PartialEq<&str> for FixedString<N> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == Ok(*other)
    }
}

impl<const N: usize> PartialEq<String> for FixedString<N> {
    fn eq(&self, other: &String) -> bool {
        self.as_str().is_ok_and(|s| s == other)
    }
}

/// Errors that can occur when creating or manipulating FixedString instances
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixedStringError {
    /// The input string is too long for the fixed-size buffer
    TooLong { max_len: usize, actual_len: usize },
}

impl fmt::Display for FixedStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FixedStringError::TooLong {
                max_len,
                actual_len,
            } => {
                write!(f, "String too long: {actual_len} bytes (max {max_len})")
            }
        }
    }
}

impl std::error::Error for FixedStringError {}

// SMPP-specific type aliases for common field sizes
// Note: ServiceType, SourceAddr, DestinationAddr, ScheduleDeliveryTime, and ValidityPeriod
// are now strongly-typed in their own modules
pub type SystemId = FixedString<16>; // 15 chars + null terminator
pub type Password = FixedString<9>; // 8 chars + null terminator
pub type SystemType = FixedString<13>; // 12 chars + null terminator
pub type AddressRange = FixedString<41>; // 40 chars + null terminator
pub type MessageId = FixedString<66>; // 65 chars + null terminator

/// A length-prefixed message (not null-terminated)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ShortMessage {
    data: [u8; 254],
    length: u8,
}

impl ShortMessage {
    /// Creates a new ShortMessage from a byte slice
    pub fn new(data: &[u8]) -> Result<Self, FixedStringError> {
        if data.len() > 254 {
            return Err(FixedStringError::TooLong {
                max_len: 254,
                actual_len: data.len(),
            });
        }

        let mut msg_data = [0u8; 254];
        msg_data[..data.len()].copy_from_slice(data);
        Ok(Self {
            data: msg_data,
            length: data.len() as u8,
        })
    }

    /// Returns the message content as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.length as usize]
    }

    /// Returns the message content as a str
    pub fn as_str(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(self.as_bytes())
    }

    /// Returns the length of the message
    pub fn len(&self) -> u8 {
        self.length
    }

    /// Returns true if the message is empty
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the underlying byte array (full 254 bytes)
    pub const fn as_full_array(&self) -> &[u8; 254] {
        &self.data
    }
}

impl fmt::Display for ShortMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "<invalid UTF-8>"),
        }
    }
}

impl fmt::Debug for ShortMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "ShortMessage(\"{s}\")"),
            Err(_) => write!(f, "ShortMessage({:?})", self.as_bytes()),
        }
    }
}

impl Default for ShortMessage {
    fn default() -> Self {
        Self {
            data: [0u8; 254],
            length: 0,
        }
    }
}

impl From<&str> for ShortMessage {
    fn from(s: &str) -> Self {
        s.parse().expect("Message too long for ShortMessage")
    }
}

impl TryFrom<String> for ShortMessage {
    type Error = FixedStringError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl FromStr for ShortMessage {
    type Err = FixedStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.as_bytes())
    }
}

// Zero-copy parsing helpers for SMPP frame parsing
impl<const N: usize> FixedString<N> {
    /// Creates a FixedString from a parsed C-string, converting from String
    pub fn from_parsed_string(s: String) -> Result<Self, FixedStringError> {
        s.parse()
    }
}

impl ShortMessage {
    /// Creates a ShortMessage from a parsed string
    pub fn from_parsed_string(s: String) -> Result<Self, FixedStringError> {
        s.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_string_creation() {
        let system_id = "test_system".parse::<SystemId>().unwrap();
        assert_eq!(system_id.as_str().unwrap(), "test_system");
        assert_eq!(system_id.len(), 11);
    }

    #[test]
    fn test_fixed_string_too_long() {
        let long_string = "a".repeat(20);
        let result = long_string.parse::<SystemId>();
        assert!(matches!(result, Err(FixedStringError::TooLong { .. })));
    }

    #[test]
    fn test_fixed_string_display() {
        let system_id = "test".parse::<SystemId>().unwrap();
        assert_eq!(format!("{system_id}"), "test");
    }

    #[test]
    fn test_short_message() {
        let msg = "Hello, world!".parse::<ShortMessage>().unwrap();
        assert_eq!(msg.as_str().unwrap(), "Hello, world!");
        assert_eq!(msg.len(), 13);
    }

    #[test]
    fn test_short_message_too_long() {
        let long_msg = "x".repeat(255);
        let result = long_msg.parse::<ShortMessage>();
        assert!(matches!(result, Err(FixedStringError::TooLong { .. })));
    }

    #[test]
    fn test_fixed_string_null_padding() {
        let system_id = "test".parse::<SystemId>().unwrap();
        let bytes = system_id.as_bytes();
        assert_eq!(bytes[4], 0); // Should be null-padded
        assert_eq!(bytes[15], 0); // Last byte should be null
    }

    #[test]
    fn test_empty_fixed_string() {
        let empty = SystemId::default();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.as_str().unwrap(), "");
    }
}
