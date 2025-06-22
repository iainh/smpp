use num_enum::TryFromPrimitive;
/// The command_status field of an SMPP message response indicates the success
/// or failure of an SMPP request. It is relevant only in the SMPP response
/// message and should be set to NULL inSMPP request messages. The SMPP Error
/// status codes are returned by the SMSC in the command_status field  of the
/// SMPP message header and in the error_status_code field of a
/// submit_multi_resp message

#[derive(TryFromPrimitive)]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CommandStatus {
    /// No Error
    Ok = 0x00000000,

    /// Message Length is invalid
    InvalidMsgLength = 0x00000001,

    /// Command Length is invalid
    InvalidCommandLength = 0x00000002,

    /// Invalid Command ID
    InvalidCommandId = 0x00000003,

    /// Incorrect BIND Status for given command
    IncorrectBindStatus = 0x00000004,

    /// ESME Already in Bound State
    AlreadyBoundState = 0x00000005,

    /// Invalid Priority Flag
    InvalidPriorityFlag = 0x00000006,

    /// Invalid Registered Delivery Flag
    InvalidRegisteredDeliveryFlag = 0x00000007,

    /// System Error
    SystemError = 0x00000008,

    // Reserved   0x00000009
    /// Invalid Source Address
    InvalidSourceAddress = 0x0000000A,

    /// Invalid Dest Addr
    InvalidDestinationAddress = 0x0000000B,

    /// Message ID is invalid
    InvalidMessageId = 0x0000000C,

    /// Bind Failed
    BindFailed = 0x0000000D,

    /// Invalid Password
    InvalidPassword = 0x0000000E,

    /// Invalid System ID
    InvalidSystemId = 0x0000000F,

    // Reserved 0x00000010
    /// Cancel SM Failed
    CancelSmFailed = 0x00000011,

    // Reserved 0x00000012
    /// Replace SM Failed
    ReplacedSmFailed = 0x00000013,

    /// Message Queue Full
    MessageQueueFull = 0x00000014,

    /// Invalid Service Type
    InvalidServiceType = 0x00000015,

    // Reserved 0x00000016 - 0x00000032
    /// Invalid number of destinations
    InvalidNumberOfDestinations = 0x00000033,

    /// Invalid Distribution List name
    InvalidDistributionListName = 0x00000034,

    // Reserved 0x00000035 - 0x0000003F
    /// Destination flag is invalid (submit_multi)
    InvalidDestinationFlag = 0x00000040,

    // Reserved    0x00000041
    /// Invalid 'submit with replace' request
    /// (i.e. submit_sm with replace_if_present_flag set)
    InvalidSubmitWithReplaceRequest = 0x00000042,

    /// Invalid esm_class field data
    InvalidEsmClassFieldData = 0x00000043,

    /// Cannot Submit to Distribution List
    CannotSubmitToDistributionList = 0x00000044,

    /// submit_sm or submit_multi failed
    SubmitFailed = 0x00000045,

    // Reserved 0x00000046 - 0x00000047
    /// Invalid Source address TON
    InvalidSourceAddressTon = 0x00000048,

    /// Invalid Source address NPI
    InvalidSourceAddressNpi = 0x00000049,

    /// Invalid Destination address TON
    InvalidDestinationAddressTon = 0x00000050,

    /// Invalid Destination address NPI
    InvalidDestinationAddressNpi = 0x00000051,

    // Reserved 0x00000052
    /// Invalid system_type field
    InvalidSystemTypeField = 0x00000053,
    /// Invalid replace_if_present flag
    InvalidReplaceIfPresentFlag = 0x00000054,
    /// Invalid number of messages
    InvalidNumberOfMessages = 0x00000055,

    // Reserved 0x00000056 - 0x00000057
    /// Throttling error (ESME has exceeded allowed message limits)
    ThrottlingError = 0x00000058,

    // Reserved 0x00000059 - 0x00000060
    /// Invalid Scheduled Delivery Time
    InvalidScheduledDeliveryTime = 0x00000061,
    /// Invalid message validity period (Expiry time)
    InvalidExpiryTime = 0x00000062,
    /// Predefined Message Invalid or Not Found
    InvalidPredefinedMessageId = 0x00000063,
    /// ESME Receiver Temporary App Error Code
    ReceiverTemporaryAppError = 0x00000064,
    /// ESME Receiver Permanent App Error Code
    ReceiverPermanentAppError = 0x00000065,
    /// ESME Receiver Reject Message Error Code
    ReceiverRejectMessageError = 0x00000066,
    /// query_sm request failed
    QuerySmRequestFailed = 0x00000067,

    // Reserved 0x00000068 - 0x000000BF
    /// Error in the optional part of the PDU Body.
    ErrorInOptionalPartofPduBody = 0x000000C0,
    /// Optional Parameter not allowed
    OptionalParameterNotAllowed = 0x000000C1,
    /// Invalid Parameter Length.
    InvalidParameterLength = 0x000000C2,
    /// Expected Optional Parameter missing
    ExpectedOptionalParameterMissing = 0x000000C3,
    /// Invalid Optional Parameter Value
    InvalidOptionalParameterValue = 0x000000C4,

    // Reserved 0x000000C5 - 0x000000FD
    /// Delivery Failure (used for data_sm_resp)
    DeliveryFailed = 0x000000FE,

    // Unknown Error
    UnknownError = 0x000000FF,
    // Reserved for SMPP extension
    // 0x00000100- 0x000003FF
    //Reserved for SMPP extension
    //Reserved for SMSC vendor specific errors
    // 0x00000400- 0x000004FF
    //Reserved for SMSC vendor specific errors
    // Reserved 0x00000500- 0xFFFFFFFF
}
