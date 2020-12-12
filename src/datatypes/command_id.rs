use num_enum::TryFromPrimitive;

#[derive(TryFromPrimitive)]
#[repr(u32)]
#[derive(Clone, Debug, PartialEq)]
pub enum CommandId {
    GenericNack = 0x80000000,
    BindReceiver = 0x00000001,
    BindReceiverResp = 0x80000001,
    BindTransmitter = 0x00000002,
    BindTransmitterResp = 0x80000002,
    QuerySm = 0x00000003,
    QuerySmResp = 0x80000003,
    SubmitSm = 0x00000004,
    SubmitSmResp = 0x80000004,
    DeliverSm = 0x00000005,
    DeliverSmResp = 0x80000005,
    Unbind = 0x00000006,
    UnbindResp = 0x80000006,
    ReplaceSm = 0x00000007,
    ReplaceSmResp = 0x80000007,
    CancelSm = 0x00000008,
    CancelSmResp = 0x80000008,
    BindTransceiver = 0x00000009,
    BindTransceiverResp = 0x80000009,
    // Reserved 0x0000000A - 0x8000000A
    Outbind = 0x0000000B,
    // Reserved 0x0000000C - 0x00000014
    //          0x8000000B - 0x80000014
    EnquireLink = 0x00000015,
    EnquireLinkResp = 0x80000015,
    // Reserved 0x00000016 - 0x00000020
    //          0x80000016 - 0x80000020
    SubmitMulti = 0x00000021,
    SubmitMultiResp = 0x80000021,
    // Reserved 0x00000022 - 0x000000FF
    //          0x80000022 - 0x800000FF
    // Reserved 0x00000100
    // Reserved 0x80000100
    // Reserved 0x00000101 - 0x80000101
    AlertNotification = 0x00000102,
    // Reserved 0x80000102
    DataSm = 0x00000103,
    DataSmResp = 0x80000103,
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
