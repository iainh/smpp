use num_enum::TryFromPrimitive;

#[derive(TryFromPrimitive)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TypeOfNumber {
    Unknown = 00000000,
    International = 00000001,
    National = 00000010,
    NetworkSpecific = 00000011,
    SubscriberNumber = 00000100,
    Alphanumeric = 00000101,
    Abbreviated = 00000110,
}
