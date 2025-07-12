// ABOUTME: Defines SMPP v3.4 command status codes per specification Section 5.1.3
// ABOUTME: Implements error code validation and provides comprehensive error categorization

use num_enum::TryFromPrimitive;

/// SMPP v3.4 Command Status Codes (Section 5.1.3)
///
/// The command_status field indicates the success or failure of an SMPP request.
/// Per SMPP v3.4 specification Section 2.2.1, this is a 4-octet field in the PDU header.
///
/// ## Usage Rules (Section 5.1.3)
/// - **Request PDUs**: Must always set command_status to 0x00000000 (Ok)
/// - **Response PDUs**: Contains the actual result code indicating success or failure
/// - **Error Responses**: SMSC returns error codes in the command_status field
///
/// ## Error Code Categories
/// - **0x00000000**: Success
/// - **0x00000001-0x000000FF**: Standard SMPP errors  
/// - **0x00000100-0x000003FF**: Reserved for SMPP extension
/// - **0x00000400-0x000004FF**: Reserved for SMSC vendor specific errors
/// - **0x00000500-0xFFFFFFFF**: Reserved
///
/// ## Related Fields
/// Error codes also appear in the error_status_code field of submit_multi_resp PDUs
/// for individual destination failures (Section 4.5.2).
///
/// ## References
/// - SMPP v3.4 Specification Section 5.1.3 (SMPP Error Status Codes)
/// - SMPP v3.4 Specification Section 2.2.1 (PDU Header Format)
/// - SMPP v3.4 Specification Table 5-2 (Error Code Definitions)

#[derive(TryFromPrimitive)]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CommandStatus {
    // Success Status (Table 5-2)
    /// No Error - Operation completed successfully
    Ok = 0x0000_0000,

    // PDU Format Errors (Table 5-2)
    /// Message Length is invalid - PDU exceeds maximum size or is too small
    InvalidMsgLength = 0x0000_0001,

    /// Command Length is invalid - command_length field value is incorrect
    InvalidCommandLength = 0x0000_0002,

    /// Invalid Command ID - Unrecognized command_id in PDU header
    InvalidCommandId = 0x0000_0003,

    // Session State Errors (Table 5-2)
    /// Incorrect BIND Status for given command - Operation not allowed in current bind state
    IncorrectBindStatus = 0x0000_0004,

    /// ESME Already in Bound State - Attempting to bind when already bound
    AlreadyBoundState = 0x0000_0005,

    // Parameter Validation Errors (Table 5-2)
    /// Invalid Priority Flag - priority_flag field contains invalid value (valid: 0-3)
    InvalidPriorityFlag = 0x0000_0006,

    /// Invalid Registered Delivery Flag - registered_delivery field has invalid bits set
    InvalidRegisteredDeliveryFlag = 0x0000_0007,

    // System Errors (Table 5-2)
    /// System Error - Internal SMSC error occurred during processing
    SystemError = 0x0000_0008,

    // Reserved   0x00000009 (Table 5-2)

    // Address Validation Errors (Table 5-2)
    /// Invalid Source Address - source_addr field format invalid for given TON/NPI
    InvalidSourceAddress = 0x0000_000A,

    /// Invalid Destination Address - destination_addr field format invalid for given TON/NPI  
    InvalidDestinationAddress = 0x0000_000B,

    /// Message ID is invalid - message_id format invalid or message not found
    InvalidMessageId = 0x0000_000C,

    // Authentication Errors (Table 5-2)
    /// Bind Failed - Authentication or authorization failure during bind
    BindFailed = 0x0000_000D,

    /// Invalid Password - password field does not match SMSC configuration
    InvalidPassword = 0x0000_000E,

    /// Invalid System ID - system_id field not recognized by SMSC
    InvalidSystemId = 0x0000_000F,

    // Reserved 0x00000010
    /// Cancel SM Failed
    CancelSmFailed = 0x0000_0011,

    // Reserved 0x00000012
    /// Replace SM Failed
    ReplacedSmFailed = 0x0000_0013,

    /// Message Queue Full
    MessageQueueFull = 0x0000_0014,

    /// Invalid Service Type
    InvalidServiceType = 0x0000_0015,

    // Reserved 0x00000016 - 0x00000032
    /// Invalid number of destinations
    InvalidNumberOfDestinations = 0x0000_0033,

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
