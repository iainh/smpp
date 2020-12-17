use num_enum::TryFromPrimitive;

#[derive(TryFromPrimitive)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TypeOfNumber {
    Unknown = 0b00000000,
    International = 0b00000001,
    National = 0b00000010,
    NetworkSpecific = 0b00000011,
    SubscriberNumber = 0b00000100,
    Alphanumeric = 0b00000101,
    Abbreviated = 0b00000110,
}
