use num_enum::TryFromPrimitive;

#[derive(TryFromPrimitive)]
#[repr(u32)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum CommandId {
    GenericNack = 0x8000_0000,
    BindReceiver = 0x0000_0001,
    BindReceiverResp = 0x8000_0001,
    BindTransmitter = 0x0000_0002,
    BindTransmitterResp = 0x8000_0002,
    QuerySm = 0x0000_0003,
    QuerySmResp = 0x8000_0003,
    SubmitSm = 0x0000_0004,
    SubmitSmResp = 0x8000_0004,
    DeliverSm = 0x0000_0005,
    DeliverSmResp = 0x8000_0005,
    Unbind = 0x0000_0006,
    UnbindResp = 0x8000_0006,
    ReplaceSm = 0x0000_0007,
    ReplaceSmResp = 0x8000_0007,
    CancelSm = 0x0000_0008,
    CancelSmResp = 0x8000_0008,
    BindTransceiver = 0x0000_0009,
    BindTransceiverResp = 0x8000_0009,
    // Reserved 0x0000000A - 0x8000000A
    Outbind = 0x0000_000B,
    // Reserved 0x0000000C - 0x00000014
    //          0x8000000B - 0x80000014
    EnquireLink = 0x0000_0015,
    EnquireLinkResp = 0x8000_0015,
    // Reserved 0x00000016 - 0x00000020
    //          0x80000016 - 0x80000020
    SubmitMulti = 0x0000_0021,
    SubmitMultiResp = 0x8000_0021,
    // Reserved 0x00000022 - 0x000000FF
    //          0x80000022 - 0x800000FF
    // Reserved 0x00000100
    // Reserved 0x80000100
    // Reserved 0x00000101 - 0x80000101
    AlertNotification = 0x0000_0102,
    // Reserved 0x80000102
    DataSm = 0x0000_0103,
    DataSmResp = 0x8000_0103,
    // Reserved for SMPP extension
    //          0x00000104 - 0x0000FFFF
    //          0x80000104 - 0x8000FFFF
    // Reserved 0x00010000 - 0x000101FF
    //          0x80010000 - 0x800101FF
    // Reserved for SMSC Vendor
    //          0x00010200 - 0x000102FF
    //          0x80010200 - 0x800102FF
    // Reserved 0x00010300 - 0xFFFFFFFF
}
