use num_enum::TryFromPrimitive;

/// This parameter is used to indicate the version of the SMPP protocol.
#[derive(TryFromPrimitive)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum InterfaceVersion {
    SmppV33 = 0x33,
    SmppV34 = 0x34,
}
