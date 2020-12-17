use num_enum::TryFromPrimitive;

#[derive(TryFromPrimitive)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum NumericPlanIndicator {
    Unknown = 0b00000000,
    ISDN = 0b00000001,
    Data = 0b00000011,
    Telex = 0b00000100,
    LandMobile = 0b00000110,
    National = 0b00001000,
    Private = 0b00001001,
    ERMES = 0b00001010,
    Internet = 0b00001110,
    WAPClientId = 0b00010010,
}
