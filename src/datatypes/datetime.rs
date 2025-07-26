// ABOUTME: Strongly-typed SMPP date/time types with format validation
// ABOUTME: Provides compile-time guarantees for YYMMDDhhmmsstnnp timestamp format

use std::fmt;
use std::str;

/// A strongly-typed SMPP date/time in YYMMDDhhmmsstnnp format
/// YY = year (00-99), MM = month (01-12), DD = day (01-31)
/// hh = hour (00-23), mm = minute (00-59), ss = second (00-59)
/// t = tenths of second (0-9), nn = UTC offset hours, p = UTC offset sign (+/-)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SmppDateTime {
    data: [u8; 16], // 16 chars exactly, no null terminator needed
    is_empty: bool, // Track if this represents "immediate" (empty) time
}

/// Date and time components for constructing SmppDateTime
#[derive(Debug, Clone, Copy)]
pub struct DateTimeComponents {
    pub year: u8,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub tenth: u8,
    pub utc_offset_hours: u8,
    pub utc_sign: char,
}

impl SmppDateTime {
    /// Creates a new SmppDateTime with full format validation
    pub fn new(datetime_str: &str) -> Result<Self, DateTimeError> {
        if datetime_str.is_empty() {
            // Empty string means "immediate" delivery
            return Ok(Self::immediate());
        }

        if datetime_str.len() != 16 {
            return Err(DateTimeError::InvalidLength {
                expected: 16,
                actual: datetime_str.len(),
            });
        }

        let bytes = datetime_str.as_bytes();

        // Validate format: YYMMDDhhmmsstnnp
        // Positions 0-12 must be digits, position 13-14 can be digits, position 15 must be +/- or R
        for (i, &byte) in bytes.iter().enumerate() {
            match i {
                0..=12 => {
                    if !byte.is_ascii_digit() {
                        return Err(DateTimeError::InvalidCharacter {
                            position: i,
                            character: byte as char,
                            expected: "digit".to_string(),
                        });
                    }
                }
                13..=14 => {
                    // UTC offset hours - must be digits
                    if !byte.is_ascii_digit() {
                        return Err(DateTimeError::InvalidCharacter {
                            position: i,
                            character: byte as char,
                            expected: "digit for UTC offset".to_string(),
                        });
                    }
                }
                15 => {
                    // UTC offset sign - must be +, -, or R (relative)
                    if byte != b'+' && byte != b'-' && byte != b'R' {
                        return Err(DateTimeError::InvalidCharacter {
                            position: i,
                            character: byte as char,
                            expected: "+, -, or R".to_string(),
                        });
                    }
                }
                _ => unreachable!(),
            }
        }

        // Validate ranges for date/time components
        let _year = parse_two_digits(&bytes[0..2])?;
        let month = parse_two_digits(&bytes[2..4])?;
        let day = parse_two_digits(&bytes[4..6])?;
        let hour = parse_two_digits(&bytes[6..8])?;
        let minute = parse_two_digits(&bytes[8..10])?;
        let second = parse_two_digits(&bytes[10..12])?;
        let tenth = bytes[12] - b'0';
        let utc_offset = parse_two_digits(&bytes[13..15])?;

        // Validate ranges
        if !(1..=12).contains(&month) {
            return Err(DateTimeError::InvalidRange {
                field: "month".to_string(),
                value: month as u32,
                min: 1,
                max: 12,
            });
        }
        if !(1..=31).contains(&day) {
            return Err(DateTimeError::InvalidRange {
                field: "day".to_string(),
                value: day as u32,
                min: 1,
                max: 31,
            });
        }
        if hour > 23 {
            return Err(DateTimeError::InvalidRange {
                field: "hour".to_string(),
                value: hour as u32,
                min: 0,
                max: 23,
            });
        }
        if minute > 59 {
            return Err(DateTimeError::InvalidRange {
                field: "minute".to_string(),
                value: minute as u32,
                min: 0,
                max: 59,
            });
        }
        if second > 59 {
            return Err(DateTimeError::InvalidRange {
                field: "second".to_string(),
                value: second as u32,
                min: 0,
                max: 59,
            });
        }
        if tenth > 9 {
            return Err(DateTimeError::InvalidRange {
                field: "tenth of second".to_string(),
                value: tenth as u32,
                min: 0,
                max: 9,
            });
        }
        if utc_offset > 99 {
            return Err(DateTimeError::InvalidRange {
                field: "UTC offset".to_string(),
                value: utc_offset as u32,
                min: 0,
                max: 99,
            });
        }

        let mut data = [0u8; 16];
        data.copy_from_slice(bytes);

        Ok(Self {
            data,
            is_empty: false,
        })
    }

    /// Creates an "immediate" delivery time (empty)
    pub fn immediate() -> Self {
        Self {
            data: [0u8; 16],
            is_empty: true,
        }
    }

    /// Creates a SmppDateTime for current UTC time (placeholder - would use actual time in real implementation)
    pub fn now_utc() -> Self {
        // In a real implementation, this would use chrono or std::time
        // For now, return a valid example timestamp
        Self::new("240712120000000+").unwrap()
    }

    /// Creates a SmppDateTime with specified components
    pub fn from_components(components: DateTimeComponents) -> Result<Self, DateTimeError> {
        if components.utc_sign != '+' && components.utc_sign != '-' && components.utc_sign != 'R' {
            return Err(DateTimeError::InvalidCharacter {
                position: 15,
                character: components.utc_sign,
                expected: "+, -, or R".to_string(),
            });
        }

        let datetime_str = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}{}{:02}{}",
            components.year,
            components.month,
            components.day,
            components.hour,
            components.minute,
            components.second,
            components.tenth,
            components.utc_offset_hours,
            components.utc_sign
        );

        Self::new(&datetime_str)
    }

    /// Returns true if this represents immediate delivery (empty time)
    pub fn is_immediate(&self) -> bool {
        self.is_empty
    }

    /// Returns the datetime as a string slice
    pub fn as_str(&self) -> Result<&str, str::Utf8Error> {
        if self.is_empty {
            Ok("")
        } else {
            str::from_utf8(&self.data)
        }
    }

    /// Returns the datetime as bytes
    pub fn as_bytes(&self) -> &[u8] {
        if self.is_empty { &[] } else { &self.data }
    }

    /// Returns the underlying byte array (full 16 bytes)
    pub const fn as_full_array(&self) -> &[u8; 16] {
        &self.data
    }

    /// Returns the length of the datetime string (0 for immediate, 16 for set time)
    pub fn len(&self) -> usize {
        if self.is_empty { 0 } else { 16 }
    }

    /// Returns true if this is an immediate delivery time
    pub fn is_empty(&self) -> bool {
        self.is_empty
    }

    /// Extracts the year component (00-99)
    pub fn year(&self) -> Option<u8> {
        if self.is_empty {
            None
        } else {
            Some(parse_two_digits(&self.data[0..2]).unwrap())
        }
    }

    /// Extracts the month component (01-12)
    pub fn month(&self) -> Option<u8> {
        if self.is_empty {
            None
        } else {
            Some(parse_two_digits(&self.data[2..4]).unwrap())
        }
    }

    /// Extracts the day component (01-31)
    pub fn day(&self) -> Option<u8> {
        if self.is_empty {
            None
        } else {
            Some(parse_two_digits(&self.data[4..6]).unwrap())
        }
    }

    /// Extracts the hour component (00-23)
    pub fn hour(&self) -> Option<u8> {
        if self.is_empty {
            None
        } else {
            Some(parse_two_digits(&self.data[6..8]).unwrap())
        }
    }

    /// Extracts the minute component (00-59)
    pub fn minute(&self) -> Option<u8> {
        if self.is_empty {
            None
        } else {
            Some(parse_two_digits(&self.data[8..10]).unwrap())
        }
    }

    /// Extracts the second component (00-59)
    pub fn second(&self) -> Option<u8> {
        if self.is_empty {
            None
        } else {
            Some(parse_two_digits(&self.data[10..12]).unwrap())
        }
    }

    /// Extracts the tenth of second component (0-9)
    pub fn tenth(&self) -> Option<u8> {
        if self.is_empty {
            None
        } else {
            Some(self.data[12] - b'0')
        }
    }

    /// Extracts the UTC offset hours (00-99)
    pub fn utc_offset_hours(&self) -> Option<u8> {
        if self.is_empty {
            None
        } else {
            Some(parse_two_digits(&self.data[13..15]).unwrap())
        }
    }

    /// Extracts the UTC offset sign (+, -, or R)
    pub fn utc_offset_sign(&self) -> Option<char> {
        if self.is_empty {
            None
        } else {
            Some(self.data[15] as char)
        }
    }

    /// Creates a SmppDateTime from a parsed C-string, for frame parsing compatibility
    pub fn from_parsed_string(s: String) -> Result<Self, DateTimeError> {
        if s.is_empty() {
            Ok(Self::immediate())
        } else {
            Self::new(&s)
        }
    }
}

/// Helper function to parse two ASCII digits into a u8
fn parse_two_digits(bytes: &[u8]) -> Result<u8, DateTimeError> {
    if bytes.len() != 2 {
        return Err(DateTimeError::InvalidLength {
            expected: 2,
            actual: bytes.len(),
        });
    }

    if !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return Err(DateTimeError::InvalidCharacter {
            position: 0,
            character: bytes[0] as char,
            expected: "digit".to_string(),
        });
    }

    Ok((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
}

/// Errors that can occur when creating or validating SMPP date/time
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DateTimeError {
    /// The datetime string has wrong length
    InvalidLength { expected: usize, actual: usize },
    /// Invalid character at specific position
    InvalidCharacter {
        position: usize,
        character: char,
        expected: String,
    },
    /// Numeric value out of valid range
    InvalidRange {
        field: String,
        value: u32,
        min: u32,
        max: u32,
    },
}

impl fmt::Display for DateTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DateTimeError::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "Invalid datetime length: {actual} chars (expected {expected})"
                )
            }
            DateTimeError::InvalidCharacter {
                position,
                character,
                expected,
            } => {
                write!(
                    f,
                    "Invalid character '{character}' at position {position} (expected {expected})"
                )
            }
            DateTimeError::InvalidRange {
                field,
                value,
                min,
                max,
            } => {
                write!(f, "Invalid {field} value: {value} (must be {min}-{max})")
            }
        }
    }
}

impl std::error::Error for DateTimeError {}

// SMPP-specific datetime type aliases
pub type ScheduleDeliveryTime = SmppDateTime;
pub type ValidityPeriod = SmppDateTime;

// Default implementation (immediate delivery)
impl Default for SmppDateTime {
    fn default() -> Self {
        Self::immediate()
    }
}

// Display implementation
impl fmt::Display for SmppDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty {
            write!(f, "immediate")
        } else {
            match self.as_str() {
                Ok(s) => write!(f, "{s}"),
                Err(_) => write!(f, "<invalid UTF-8>"),
            }
        }
    }
}

impl fmt::Debug for SmppDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty {
            write!(f, "SmppDateTime::immediate()")
        } else {
            match self.as_str() {
                Ok(s) => write!(f, "SmppDateTime(\"{s}\")"),
                Err(_) => write!(f, "SmppDateTime({:?})", self.as_bytes()),
            }
        }
    }
}

// AsRef implementation for serialization
impl AsRef<[u8]> for SmppDateTime {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

// Comparison implementations
impl PartialEq<str> for SmppDateTime {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == Ok(other)
    }
}

impl PartialEq<&str> for SmppDateTime {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == Ok(*other)
    }
}

// From implementations for common cases
impl From<&str> for SmppDateTime {
    fn from(s: &str) -> Self {
        if s.is_empty() {
            Self::immediate()
        } else {
            Self::new(s).expect("Invalid SMPP datetime format")
        }
    }
}

impl TryFrom<String> for SmppDateTime {
    type Error = DateTimeError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty() {
            Ok(Self::immediate())
        } else {
            Self::new(&s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smpp_datetime_valid() {
        let dt = SmppDateTime::new("240712120000000+").unwrap();
        assert_eq!(dt.as_str().unwrap(), "240712120000000+");
        assert_eq!(dt.len(), 16);
        assert!(!dt.is_immediate());
    }

    #[test]
    fn test_smpp_datetime_immediate() {
        let dt = SmppDateTime::immediate();
        assert_eq!(dt.as_str().unwrap(), "");
        assert_eq!(dt.len(), 0);
        assert!(dt.is_immediate());
    }

    #[test]
    fn test_smpp_datetime_from_empty_string() {
        let dt = SmppDateTime::from("");
        assert!(dt.is_immediate());
        assert_eq!(dt.len(), 0);
    }

    #[test]
    fn test_smpp_datetime_invalid_length() {
        let result = SmppDateTime::new("240712120000000"); // 15 chars, need 16
        assert!(matches!(result, Err(DateTimeError::InvalidLength { .. })));
    }

    #[test]
    fn test_smpp_datetime_invalid_character() {
        let result = SmppDateTime::new("24071212000000a+"); // 'a' instead of digit
        assert!(matches!(
            result,
            Err(DateTimeError::InvalidCharacter { .. })
        ));
    }

    #[test]
    fn test_smpp_datetime_invalid_utc_sign() {
        let result = SmppDateTime::new("240712120000000x"); // 'x' instead of +/-/R
        assert!(matches!(
            result,
            Err(DateTimeError::InvalidCharacter { .. })
        ));
    }

    #[test]
    fn test_smpp_datetime_invalid_month() {
        let result = SmppDateTime::new("241312120000000+"); // month = 13
        assert!(matches!(result, Err(DateTimeError::InvalidRange { .. })));
    }

    #[test]
    fn test_smpp_datetime_invalid_day() {
        let result = SmppDateTime::new("240732120000000+"); // day = 32
        assert!(matches!(result, Err(DateTimeError::InvalidRange { .. })));
    }

    #[test]
    fn test_smpp_datetime_invalid_hour() {
        let result = SmppDateTime::new("240712250000000+"); // hour = 25
        assert!(matches!(result, Err(DateTimeError::InvalidRange { .. })));
    }

    #[test]
    fn test_smpp_datetime_from_components() {
        let dt = SmppDateTime::from_components(DateTimeComponents {
            year: 24,
            month: 7,
            day: 12,
            hour: 12,
            minute: 30,
            second: 45,
            tenth: 5,
            utc_offset_hours: 0,
            utc_sign: '+',
        })
        .unwrap();
        assert_eq!(dt.as_str().unwrap(), "240712123045500+");
        assert_eq!(dt.year(), Some(24));
        assert_eq!(dt.month(), Some(7));
        assert_eq!(dt.day(), Some(12));
        assert_eq!(dt.hour(), Some(12));
        assert_eq!(dt.minute(), Some(30));
        assert_eq!(dt.second(), Some(45));
        assert_eq!(dt.tenth(), Some(5));
        assert_eq!(dt.utc_offset_hours(), Some(0));
        assert_eq!(dt.utc_offset_sign(), Some('+'));
    }

    #[test]
    fn test_smpp_datetime_component_extraction() {
        let dt = SmppDateTime::new("240712120000000+").unwrap();
        assert_eq!(dt.year(), Some(24));
        assert_eq!(dt.month(), Some(7));
        assert_eq!(dt.day(), Some(12));
        assert_eq!(dt.hour(), Some(12));
        assert_eq!(dt.minute(), Some(0));
        assert_eq!(dt.second(), Some(0));
        assert_eq!(dt.tenth(), Some(0));
        assert_eq!(dt.utc_offset_hours(), Some(0));
        assert_eq!(dt.utc_offset_sign(), Some('+'));
    }

    #[test]
    fn test_smpp_datetime_immediate_components() {
        let dt = SmppDateTime::immediate();
        assert_eq!(dt.year(), None);
        assert_eq!(dt.month(), None);
        assert_eq!(dt.day(), None);
        assert_eq!(dt.hour(), None);
        assert_eq!(dt.minute(), None);
        assert_eq!(dt.second(), None);
        assert_eq!(dt.tenth(), None);
        assert_eq!(dt.utc_offset_hours(), None);
        assert_eq!(dt.utc_offset_sign(), None);
    }

    #[test]
    fn test_smpp_datetime_display() {
        let dt = SmppDateTime::new("240712120000000+").unwrap();
        assert_eq!(format!("{dt}"), "240712120000000+");

        let immediate = SmppDateTime::immediate();
        assert_eq!(format!("{immediate}"), "immediate");
    }

    #[test]
    fn test_smpp_datetime_utc_variations() {
        // Test with minus UTC offset
        let dt_minus = SmppDateTime::new("240712120000000-").unwrap();
        assert_eq!(dt_minus.utc_offset_sign(), Some('-'));

        // Test with relative time
        let dt_relative = SmppDateTime::new("240712120000000R").unwrap();
        assert_eq!(dt_relative.utc_offset_sign(), Some('R'));
    }

    #[test]
    fn test_smpp_datetime_edge_cases() {
        // Test maximum valid values
        let dt_max = SmppDateTime::new("991231235959999+").unwrap();
        assert_eq!(dt_max.year(), Some(99));
        assert_eq!(dt_max.month(), Some(12));
        assert_eq!(dt_max.day(), Some(31));
        assert_eq!(dt_max.hour(), Some(23));
        assert_eq!(dt_max.minute(), Some(59));
        assert_eq!(dt_max.second(), Some(59));
        assert_eq!(dt_max.tenth(), Some(9));
        assert_eq!(dt_max.utc_offset_hours(), Some(99));

        // Test minimum valid values
        let dt_min = SmppDateTime::new("000101000000000+").unwrap();
        assert_eq!(dt_min.year(), Some(0));
        assert_eq!(dt_min.month(), Some(1));
        assert_eq!(dt_min.day(), Some(1));
    }
}
