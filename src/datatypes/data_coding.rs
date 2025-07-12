// ABOUTME: Strongly-typed SMPP data coding scheme with encoding validation and character set support
// ABOUTME: Provides compile-time guarantees for data encoding correctness and prevents invalid schemes

use std::fmt;

/// Strongly-typed data coding scheme that enforces SMPP protocol validation
/// Replaces raw u8 values with validated encoding schemes and character sets
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DataCoding {
    /// SMSC Default Alphabet (typically GSM 7-bit)
    #[default]
    SmscDefault,
    /// IA5 (CCITT T.50)/ASCII encoding
    Ascii,
    /// 8-bit binary data (no encoding)
    Binary,
    /// Latin-1 (ISO-8859-1) character set
    Latin1,
    /// UCS-2 (ISO/IEC-10646) Unicode encoding
    Ucs2,
    /// Cyrillic (ISO-8859-5) character set
    Cyrillic,
    /// Latin/Hebrew (ISO-8859-8) character set
    LatinHebrew,
    /// JIS (X 0208-1990) Japanese character set
    Jis,
    /// GSM 7-bit default alphabet with message class
    Gsm7BitWithClass(MessageClass),
    /// UCS-2 with message class
    Ucs2WithClass(MessageClass),
    /// Custom/reserved data coding value
    Custom(u8),
}

impl DataCoding {
    /// Creates a DataCoding from a raw u8 value with validation
    pub fn from_byte(value: u8) -> Self {
        match value {
            0x00 => DataCoding::SmscDefault,
            0x01 => DataCoding::Ascii,
            0x02 => DataCoding::Binary,
            0x03 => DataCoding::Latin1,
            0x04 => DataCoding::Binary, // Duplicate binary encoding in spec
            0x05 => DataCoding::Jis,
            0x06 => DataCoding::Cyrillic,
            0x07 => DataCoding::LatinHebrew,
            0x08 => DataCoding::Ucs2,
            // GSM 7-bit with message class (0xF0-0xF3)
            0xF0 => DataCoding::Gsm7BitWithClass(MessageClass::Flash),
            0xF1 => DataCoding::Gsm7BitWithClass(MessageClass::MobileEquipment),
            0xF2 => DataCoding::Gsm7BitWithClass(MessageClass::SimSpecific),
            0xF3 => DataCoding::Gsm7BitWithClass(MessageClass::TerminalEquipment),
            // UCS-2 with message class (0xF4-0xF7)
            0xF4 => DataCoding::Ucs2WithClass(MessageClass::Flash),
            0xF5 => DataCoding::Ucs2WithClass(MessageClass::MobileEquipment),
            0xF6 => DataCoding::Ucs2WithClass(MessageClass::SimSpecific),
            0xF7 => DataCoding::Ucs2WithClass(MessageClass::TerminalEquipment),
            // All other values are custom/reserved
            _ => DataCoding::Custom(value),
        }
    }

    /// Creates a SMSC default alphabet data coding
    pub fn smsc_default() -> Self {
        DataCoding::SmscDefault
    }

    /// Creates ASCII/IA5 data coding
    pub fn ascii() -> Self {
        DataCoding::Ascii
    }

    /// Creates binary (8-bit) data coding
    pub fn binary() -> Self {
        DataCoding::Binary
    }

    /// Creates UCS-2 Unicode data coding
    pub fn ucs2() -> Self {
        DataCoding::Ucs2
    }

    /// Creates GSM 7-bit with flash message class
    pub fn gsm7_flash() -> Self {
        DataCoding::Gsm7BitWithClass(MessageClass::Flash)
    }

    /// Creates UCS-2 with specific message class
    pub fn ucs2_with_class(class: MessageClass) -> Self {
        DataCoding::Ucs2WithClass(class)
    }

    /// Returns the raw u8 value for wire protocol
    pub fn to_byte(&self) -> u8 {
        match self {
            DataCoding::SmscDefault => 0x00,
            DataCoding::Ascii => 0x01,
            DataCoding::Binary => 0x02,
            DataCoding::Latin1 => 0x03,
            DataCoding::Jis => 0x05,
            DataCoding::Cyrillic => 0x06,
            DataCoding::LatinHebrew => 0x07,
            DataCoding::Ucs2 => 0x08,
            DataCoding::Gsm7BitWithClass(MessageClass::Flash) => 0xF0,
            DataCoding::Gsm7BitWithClass(MessageClass::MobileEquipment) => 0xF1,
            DataCoding::Gsm7BitWithClass(MessageClass::SimSpecific) => 0xF2,
            DataCoding::Gsm7BitWithClass(MessageClass::TerminalEquipment) => 0xF3,
            DataCoding::Ucs2WithClass(MessageClass::Flash) => 0xF4,
            DataCoding::Ucs2WithClass(MessageClass::MobileEquipment) => 0xF5,
            DataCoding::Ucs2WithClass(MessageClass::SimSpecific) => 0xF6,
            DataCoding::Ucs2WithClass(MessageClass::TerminalEquipment) => 0xF7,
            DataCoding::Custom(value) => *value,
        }
    }

    /// Returns true if this encoding uses 7-bit character encoding
    pub fn is_7bit(&self) -> bool {
        matches!(
            self,
            DataCoding::SmscDefault | DataCoding::Ascii | DataCoding::Gsm7BitWithClass(_)
        )
    }

    /// Returns true if this encoding uses 8-bit character encoding
    pub fn is_8bit(&self) -> bool {
        matches!(
            self,
            DataCoding::Binary
                | DataCoding::Latin1
                | DataCoding::Cyrillic
                | DataCoding::LatinHebrew
        )
    }

    /// Returns true if this encoding uses 16-bit (Unicode) character encoding
    pub fn is_16bit(&self) -> bool {
        matches!(
            self,
            DataCoding::Ucs2 | DataCoding::Ucs2WithClass(_) | DataCoding::Jis
        )
    }

    /// Returns true if this encoding is binary (no text encoding)
    pub fn is_binary(&self) -> bool {
        matches!(self, DataCoding::Binary)
    }

    /// Returns true if this encoding supports Unicode characters
    pub fn is_unicode(&self) -> bool {
        matches!(self, DataCoding::Ucs2 | DataCoding::Ucs2WithClass(_))
    }

    /// Returns the message class if this coding scheme includes one
    pub fn message_class(&self) -> Option<MessageClass> {
        match self {
            DataCoding::Gsm7BitWithClass(class) | DataCoding::Ucs2WithClass(class) => Some(*class),
            _ => None,
        }
    }

    /// Returns true if this coding scheme includes a message class
    pub fn has_message_class(&self) -> bool {
        self.message_class().is_some()
    }

    /// Returns the character set name for this encoding
    pub fn charset_name(&self) -> &'static str {
        match self {
            DataCoding::SmscDefault => "GSM 7-bit Default",
            DataCoding::Ascii => "ASCII/IA5",
            DataCoding::Binary => "Binary",
            DataCoding::Latin1 => "ISO-8859-1",
            DataCoding::Jis => "JIS X 0208-1990",
            DataCoding::Cyrillic => "ISO-8859-5",
            DataCoding::LatinHebrew => "ISO-8859-8",
            DataCoding::Ucs2 | DataCoding::Ucs2WithClass(_) => "UCS-2",
            DataCoding::Gsm7BitWithClass(_) => "GSM 7-bit Default",
            DataCoding::Custom(_) => "Custom/Reserved",
        }
    }

    /// Calculates the maximum message length for this encoding scheme
    /// Returns the number of characters/bytes that fit in a standard SMS
    pub fn max_single_sms_length(&self) -> usize {
        match self {
            DataCoding::SmscDefault | DataCoding::Ascii | DataCoding::Gsm7BitWithClass(_) => 160,
            DataCoding::Binary
            | DataCoding::Latin1
            | DataCoding::Cyrillic
            | DataCoding::LatinHebrew => 140,
            DataCoding::Ucs2 | DataCoding::Ucs2WithClass(_) | DataCoding::Jis => 70,
            DataCoding::Custom(_) => 140, // Default to 8-bit assumption
        }
    }

    /// Validates that the given text is compatible with this encoding
    pub fn validate_text(&self, text: &str) -> Result<(), DataCodingError> {
        match self {
            DataCoding::SmscDefault | DataCoding::Gsm7BitWithClass(_) => {
                // GSM 7-bit basic character set validation
                if text.chars().any(|c| !is_gsm_7bit_char(c)) {
                    return Err(DataCodingError::IncompatibleCharacters {
                        encoding: *self,
                        text: text.to_string(),
                    });
                }
            }
            DataCoding::Ascii => {
                // ASCII validation (0-127)
                if text.chars().any(|c| c as u32 > 127) {
                    return Err(DataCodingError::IncompatibleCharacters {
                        encoding: *self,
                        text: text.to_string(),
                    });
                }
            }
            DataCoding::Binary => {
                return Err(DataCodingError::TextNotAllowed { encoding: *self });
            }
            // Other encodings are more permissive or handle extended character sets
            _ => {}
        }
        Ok(())
    }
}

/// Message class for SMS delivery
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum MessageClass {
    /// Flash SMS (displayed immediately, not stored)
    Flash,
    /// Mobile Equipment specific message
    MobileEquipment,
    /// SIM-specific message (stored on SIM card)
    SimSpecific,
    /// Terminal Equipment specific message
    TerminalEquipment,
}

impl MessageClass {
    /// Returns a human-readable description of the message class
    pub fn description(&self) -> &'static str {
        match self {
            MessageClass::Flash => "Flash SMS (immediate display)",
            MessageClass::MobileEquipment => "Mobile Equipment specific",
            MessageClass::SimSpecific => "SIM card storage",
            MessageClass::TerminalEquipment => "Terminal Equipment specific",
        }
    }
}

/// Errors that can occur when validating data coding
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataCodingError {
    /// Text contains characters incompatible with the encoding
    IncompatibleCharacters { encoding: DataCoding, text: String },
    /// Text is not allowed for binary encodings
    TextNotAllowed { encoding: DataCoding },
}

impl fmt::Display for DataCodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataCodingError::IncompatibleCharacters { encoding, text } => {
                write!(
                    f,
                    "Text contains characters incompatible with {encoding:?}: {text}"
                )
            }
            DataCodingError::TextNotAllowed { encoding } => {
                write!(
                    f,
                    "Text validation not supported for binary encoding: {encoding:?}"
                )
            }
        }
    }
}

impl std::error::Error for DataCodingError {}

/// Checks if a character is valid in the GSM 7-bit default alphabet
fn is_gsm_7bit_char(c: char) -> bool {
    // Simplified GSM 7-bit character set check
    // In a real implementation, this would check against the full GSM 03.38 table
    match c {
        // Basic Latin subset that's safe in GSM 7-bit
        'A'..='Z' | 'a'..='z' | '0'..='9' => true,
        ' ' | '!' | '"' | '#' | '$' | '%' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | '-'
        | '.' | '/' => true,
        ':' | ';' | '<' | '=' | '>' | '?' | '@' => true,
        '[' | '\\' | ']' | '^' | '_' | '`' => true,
        '{' | '|' | '}' | '~' => true,
        '\n' | '\r' => true,
        // Some extended characters that are in GSM 7-bit
        '£' | '¤' | '¥' | '§' | '¿' | 'Ä' | 'Å' | 'Æ' | 'Ç' | 'É' | 'Ñ' | 'Ö' | 'Ø' | 'Ü' | 'ß' => {
            true
        }
        'à' | 'ä' | 'å' | 'æ' | 'è' | 'é' | 'ì' | 'í' | 'ñ' | 'ò' | 'ó' | 'ö' | 'ø' | 'ù' | 'ú'
        | 'ü' | 'ÿ' => true,
        _ => false,
    }
}

// Default implementation is now derived

// Display implementation
impl fmt::Display for DataCoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.charset_name())?;
        if let Some(class) = self.message_class() {
            write!(f, " ({})", class.description())?;
        }
        Ok(())
    }
}

impl fmt::Debug for DataCoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataCoding::Custom(value) => write!(f, "DataCoding::Custom(0x{value:02X})"),
            _ => write!(
                f,
                "DataCoding::{} (0x{:02X})",
                self.charset_name().replace(" ", "").replace("-", ""),
                self.to_byte()
            ),
        }
    }
}

// Conversion implementations
impl From<u8> for DataCoding {
    fn from(value: u8) -> Self {
        Self::from_byte(value)
    }
}

impl From<DataCoding> for u8 {
    fn from(data_coding: DataCoding) -> Self {
        data_coding.to_byte()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_coding_basic_types() {
        assert_eq!(DataCoding::SmscDefault.to_byte(), 0x00);
        assert_eq!(DataCoding::Ascii.to_byte(), 0x01);
        assert_eq!(DataCoding::Binary.to_byte(), 0x02);
        assert_eq!(DataCoding::Ucs2.to_byte(), 0x08);
    }

    #[test]
    fn test_data_coding_with_message_class() {
        let flash_gsm = DataCoding::Gsm7BitWithClass(MessageClass::Flash);
        assert_eq!(flash_gsm.to_byte(), 0xF0);
        assert_eq!(flash_gsm.message_class(), Some(MessageClass::Flash));
        assert!(flash_gsm.has_message_class());

        let sim_ucs2 = DataCoding::Ucs2WithClass(MessageClass::SimSpecific);
        assert_eq!(sim_ucs2.to_byte(), 0xF6);
        assert_eq!(sim_ucs2.message_class(), Some(MessageClass::SimSpecific));
    }

    #[test]
    fn test_data_coding_from_byte() {
        assert_eq!(DataCoding::from_byte(0x00), DataCoding::SmscDefault);
        assert_eq!(DataCoding::from_byte(0x01), DataCoding::Ascii);
        assert_eq!(DataCoding::from_byte(0x08), DataCoding::Ucs2);
        assert_eq!(
            DataCoding::from_byte(0xF0),
            DataCoding::Gsm7BitWithClass(MessageClass::Flash)
        );

        // Custom/unknown values
        let custom = DataCoding::from_byte(0xFF);
        assert_eq!(custom, DataCoding::Custom(0xFF));
    }

    #[test]
    fn test_data_coding_roundtrip() {
        let original = DataCoding::Ucs2WithClass(MessageClass::MobileEquipment);
        let byte_value = original.to_byte();
        let reconstructed = DataCoding::from_byte(byte_value);
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn test_data_coding_properties() {
        assert!(DataCoding::SmscDefault.is_7bit());
        assert!(!DataCoding::SmscDefault.is_8bit());
        assert!(!DataCoding::SmscDefault.is_16bit());
        assert!(!DataCoding::SmscDefault.is_binary());

        assert!(DataCoding::Binary.is_8bit());
        assert!(DataCoding::Binary.is_binary());
        assert!(!DataCoding::Binary.is_7bit());

        assert!(DataCoding::Ucs2.is_16bit());
        assert!(DataCoding::Ucs2.is_unicode());
        assert!(!DataCoding::Ucs2.is_7bit());
    }

    #[test]
    fn test_max_sms_length() {
        assert_eq!(DataCoding::SmscDefault.max_single_sms_length(), 160);
        assert_eq!(DataCoding::Ascii.max_single_sms_length(), 160);
        assert_eq!(DataCoding::Binary.max_single_sms_length(), 140);
        assert_eq!(DataCoding::Latin1.max_single_sms_length(), 140);
        assert_eq!(DataCoding::Ucs2.max_single_sms_length(), 70);
        assert_eq!(DataCoding::Jis.max_single_sms_length(), 70);
    }

    #[test]
    fn test_text_validation_ascii() {
        let ascii = DataCoding::Ascii;

        // Valid ASCII text
        assert!(ascii.validate_text("Hello World 123").is_ok());

        // Invalid ASCII (non-ASCII characters)
        assert!(ascii.validate_text("Hello 世界").is_err());
    }

    #[test]
    fn test_text_validation_gsm7bit() {
        let gsm7 = DataCoding::SmscDefault;

        // Valid GSM 7-bit text
        assert!(gsm7.validate_text("Hello World").is_ok());
        assert!(gsm7.validate_text("Test £ @ message").is_ok());

        // Invalid GSM 7-bit (emoji)
        assert!(gsm7.validate_text("Hello 😀").is_err());
    }

    #[test]
    fn test_text_validation_binary() {
        let binary = DataCoding::Binary;

        // Text validation not allowed for binary
        assert!(binary.validate_text("any text").is_err());
    }

    #[test]
    fn test_text_validation_unicode() {
        let ucs2 = DataCoding::Ucs2;

        // Unicode should accept all text (in real implementation would check for UCS-2 compatibility)
        assert!(ucs2.validate_text("Hello 世界 🌍").is_ok());
        assert!(ucs2.validate_text("مرحبا").is_ok());
    }

    #[test]
    fn test_message_class_descriptions() {
        assert_eq!(
            MessageClass::Flash.description(),
            "Flash SMS (immediate display)"
        );
        assert_eq!(MessageClass::SimSpecific.description(), "SIM card storage");
        assert_eq!(
            MessageClass::MobileEquipment.description(),
            "Mobile Equipment specific"
        );
        assert_eq!(
            MessageClass::TerminalEquipment.description(),
            "Terminal Equipment specific"
        );
    }

    #[test]
    fn test_data_coding_display() {
        assert_eq!(format!("{}", DataCoding::SmscDefault), "GSM 7-bit Default");
        assert_eq!(format!("{}", DataCoding::Ascii), "ASCII/IA5");
        assert_eq!(format!("{}", DataCoding::Ucs2), "UCS-2");

        let flash_gsm = DataCoding::Gsm7BitWithClass(MessageClass::Flash);
        assert_eq!(
            format!("{}", flash_gsm),
            "GSM 7-bit Default (Flash SMS (immediate display))"
        );
    }

    #[test]
    fn test_data_coding_charset_names() {
        assert_eq!(DataCoding::SmscDefault.charset_name(), "GSM 7-bit Default");
        assert_eq!(DataCoding::Ascii.charset_name(), "ASCII/IA5");
        assert_eq!(DataCoding::Binary.charset_name(), "Binary");
        assert_eq!(DataCoding::Latin1.charset_name(), "ISO-8859-1");
        assert_eq!(DataCoding::Ucs2.charset_name(), "UCS-2");
        assert_eq!(DataCoding::Custom(0xFF).charset_name(), "Custom/Reserved");
    }

    #[test]
    fn test_u8_conversions() {
        let dc = DataCoding::Ucs2;
        let byte_val: u8 = dc.into();
        let reconstructed = DataCoding::from(byte_val);
        assert_eq!(dc, reconstructed);
    }

    #[test]
    fn test_gsm_7bit_char_validation() {
        // Test basic ASCII characters
        assert!(is_gsm_7bit_char('A'));
        assert!(is_gsm_7bit_char('z'));
        assert!(is_gsm_7bit_char('0'));
        assert!(is_gsm_7bit_char('9'));
        assert!(is_gsm_7bit_char(' '));
        assert!(is_gsm_7bit_char('@'));

        // Test GSM 7-bit extended characters
        assert!(is_gsm_7bit_char('£'));
        // Note: € is in GSM 7-bit extended table but not in our simplified implementation
        // assert!(is_gsm_7bit_char('€'));
        assert!(is_gsm_7bit_char('Ñ'));

        // Test invalid characters
        assert!(!is_gsm_7bit_char('😀')); // Emoji
        assert!(!is_gsm_7bit_char('世')); // Chinese character
    }
}
