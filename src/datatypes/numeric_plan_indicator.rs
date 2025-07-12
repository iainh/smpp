// ABOUTME: Defines SMPP v3.4 Numbering Plan Indicator (NPI) field values per specification
// ABOUTME: Implements numbering plan classification used with Type of Number for complete addressing

use num_enum::TryFromPrimitive;

/// SMPP v3.4 Numbering Plan Indicator (NPI) Field
///
/// Specifies the numbering plan used for source and destination addresses.
/// Used in conjunction with Type of Number (TON) to define the complete
/// addressing scheme per SMPP v3.4 specification.
///
/// ## Field Usage (SMPP v3.4)
/// - **source_addr_npi**: Numbering plan for source address (Section 4.1.1, 4.4.1, etc.)
/// - **dest_addr_npi**: Numbering plan for destination address (Section 4.1.1, 4.4.1, etc.)
/// - **addr_npi**: Numbering plan for ESME address in bind operations (Section 4.1.1)
///
/// ## Common TON/NPI Combinations
/// - **International TON + ISDN NPI**: Standard international mobile numbers (E.164)
/// - **National TON + ISDN NPI**: National mobile numbers without country code
/// - **Alphanumeric TON + Unknown NPI**: Short codes and service identifiers
/// - **Abbreviated TON + ISDN NPI**: Emergency and service numbers (911, 411)
/// - **Unknown TON + Unknown NPI**: When addressing scheme is not specified
///
/// ## Addressing Examples by NPI
/// - **ISDN (E.164)**: "+1234567890", "234567890"
/// - **Internet**: "user@domain.com", "sip:user@provider.com"  
/// - **Private**: Carrier-specific numbering schemes
/// - **National**: Country-specific national numbering plans
///
/// ## References
/// - SMPP v3.4 Specification (address format sections)
/// - ITU-T E.164 (ISDN numbering plan)
/// - ITU-T X.121 (Data network addressing)
/// - RFC 3966 (Internet telephony numbering)
#[derive(TryFromPrimitive)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum NumericPlanIndicator {
    /// Unknown numbering plan - Use when NPI is not specified
    Unknown = 0b00000000,

    /// ISDN/telephony numbering plan (ITU-T E.164)
    /// Most common for mobile SMS - standard phone numbers
    /// Example: "+1234567890", "234567890"
    Isdn = 0b00000001,

    /// Data numbering plan (ITU-T X.121)
    /// Used for packet-switched data networks
    /// Example: X.25 network addresses
    Data = 0b00000011,

    /// Telex numbering plan (ITU-T F.69)
    /// Legacy telex network addressing
    /// Example: Traditional telex numbers
    Telex = 0b00000100,

    /// Land mobile numbering plan (ITU-T E.212)
    /// Used for land mobile radio networks
    /// Example: Professional mobile radio (PMR) systems
    LandMobile = 0b00000110,

    /// National numbering plan
    /// Country-specific numbering schemes
    /// Example: National short codes, national dialing plans
    National = 0b00001000,

    /// Private numbering plan
    /// Operator or carrier-specific addressing
    /// Example: Internal network numbering, PBX extensions
    Private = 0b00001001,

    /// ERMES numbering plan (ETS 300 133)
    /// European Radio Message System addressing
    /// Example: ERMES pager addresses
    Ermes = 0b00001010,

    /// Internet numbering plan
    /// IP-based addressing schemes  
    /// Example: "user@domain.com", "sip:user@provider.com"
    Internet = 0b00001110,

    /// WAP Client ID numbering plan
    /// Wireless Application Protocol client identifiers
    /// Example: WAP push addressing
    WapClientId = 0b00010010,
}
