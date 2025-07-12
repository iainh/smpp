// ABOUTME: Defines SMPP v3.4 Type of Number (TON) field values per specification
// ABOUTME: Implements address type classification for source and destination addresses

use num_enum::TryFromPrimitive;

/// SMPP v3.4 Type of Number (TON) Field
///
/// Specifies the type of number format for source and destination addresses.
/// Used in conjunction with Numbering Plan Indicator (NPI) to define the
/// complete addressing scheme per SMPP v3.4 specification.
///
/// ## Field Usage (SMPP v3.4)
/// - **source_addr_ton**: Type of Number for source address (Section 4.1.1, 4.4.1, etc.)
/// - **dest_addr_ton**: Type of Number for destination address (Section 4.1.1, 4.4.1, etc.)
/// - **addr_ton**: Type of Number for ESME address in bind operations (Section 4.1.1)
///
/// ## Specification Reference
/// This enum implements the TON field as defined in SMPP v3.4 specification.
/// The values correspond to standard telecommunication numbering plans and
/// are typically used with specific NPI values for complete address formatting.
///
/// ## Address Format Examples
/// - **International + ISDN**: "+1234567890" (E.164 format)
/// - **National + ISDN**: "234567890" (national format without country code)
/// - **Alphanumeric**: "SHORTCODE" or "COMPANY" (text-based addressing)
/// - **Abbreviated**: "911", "411" (short dialing codes)
///
/// ## References
/// - SMPP v3.4 Specification (address format sections)
/// - ITU-T E.164 (International numbering plan)
/// - ITU-T E.212 (International identification plan)
#[derive(TryFromPrimitive)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TypeOfNumber {
    /// Unknown type - Use when TON is not specified or applicable
    Unknown = 0b00000000,

    /// International number (ITU-T E.164)
    /// Format: Country code + national number (e.g., "+1234567890")
    /// Used with: ISDN NPI (0x01) typically
    International = 0b00000001,

    /// National number  
    /// Format: National number without country code (e.g., "234567890")
    /// Used with: ISDN NPI (0x01) typically
    National = 0b00000010,

    /// Network-specific number
    /// Format: Operator-defined addressing scheme
    /// Used with: Network-specific NPI values
    NetworkSpecific = 0b00000011,

    /// Subscriber number
    /// Format: Direct subscriber addressing within network
    /// Used with: Private NPI (0x09) typically  
    SubscriberNumber = 0b00000100,

    /// Alphanumeric identifier
    /// Format: Text-based address (e.g., "COMPANY", "SHORTCODE")
    /// Used with: Unknown NPI (0x00) typically
    /// Max length: Usually limited by PDU field constraints
    Alphanumeric = 0b00000101,

    /// Abbreviated number
    /// Format: Short dial codes (e.g., "911", "411", "100")
    /// Used with: ISDN NPI (0x01) or Private NPI (0x09)
    Abbreviated = 0b00000110,
}
