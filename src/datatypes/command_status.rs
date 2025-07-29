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
    
    // SMPP v5.0 Extension Error Codes (0x00000100-0x000003FF)
    
    // Broadcast Error Codes (0x0100-0x0103)
    /// Invalid Broadcast Area Identifier - broadcast area format invalid or not supported
    InvalidBroadcastAreaIdentifier = 0x00000100,
    /// Invalid Broadcast Content Type - content type not supported or invalid format
    InvalidBroadcastContentType = 0x00000101,
    /// Invalid Broadcast Frequency - broadcast frequency outside supported range
    InvalidBroadcastFrequency = 0x00000102,
    /// Invalid Broadcast Service Group - service group identifier not recognized
    InvalidBroadcastServiceGroup = 0x00000103,
    
    // Congestion Control Error Codes (0x0104-0x0105)
    /// Congestion State Rejected - message rejected due to congestion state
    CongestionStateRejected = 0x00000104,
    /// Message Throttled - message throttled due to congestion control
    MessageThrottled = 0x00000105,
    
    // Network Validation Error Codes (0x0106-0x0107)
    /// Invalid Network ID - network identifier not recognized or invalid
    InvalidNetworkId = 0x00000106,
    /// Invalid Node ID - node identifier not recognized or invalid
    InvalidNodeId = 0x00000107,
    
    // Version Negotiation Error Codes (0x0108-0x0109)
    /// Unsupported Version - SMPP version not supported by receiver
    UnsupportedVersion = 0x00000108,
    /// Version Mismatch - version mismatch detected during negotiation
    VersionMismatch = 0x00000109,
    
    // Reserved for SMPP extension
    // 0x0000010A - 0x000003FF
    //Reserved for SMPP extension
    //Reserved for SMSC vendor specific errors
    // 0x00000400- 0x000004FF
    //Reserved for SMSC vendor specific errors
    // Reserved 0x00000500- 0xFFFFFFFF
}

impl CommandStatus {
    /// Check if this error code is related to broadcast operations (SMPP v5.0)
    pub fn is_broadcast_error(&self) -> bool {
        matches!(self, 
            CommandStatus::InvalidBroadcastAreaIdentifier |
            CommandStatus::InvalidBroadcastContentType |
            CommandStatus::InvalidBroadcastFrequency |
            CommandStatus::InvalidBroadcastServiceGroup
        )
    }
    
    /// Check if this error code is related to congestion control (SMPP v5.0)
    pub fn is_congestion_error(&self) -> bool {
        matches!(self, 
            CommandStatus::CongestionStateRejected |
            CommandStatus::MessageThrottled
        )
    }
    
    /// Check if this error code is related to network validation (SMPP v5.0)
    pub fn is_network_error(&self) -> bool {
        matches!(self, 
            CommandStatus::InvalidNetworkId |
            CommandStatus::InvalidNodeId
        )
    }
    
    /// Check if this error code is related to version negotiation (SMPP v5.0)
    pub fn is_version_error(&self) -> bool {
        matches!(self, 
            CommandStatus::UnsupportedVersion |
            CommandStatus::VersionMismatch
        )
    }
    
    /// Check if this error code is specific to SMPP v5.0
    pub fn is_v50_specific(&self) -> bool {
        (*self as u32) >= 0x00000100
    }
    
    /// Check if this error code is related to throttling/congestion
    pub fn is_throttling_related(&self) -> bool {
        matches!(self, 
            CommandStatus::ThrottlingError |
            CommandStatus::CongestionStateRejected |
            CommandStatus::MessageThrottled
        )
    }
    
    /// Get a human-readable description of the error code
    pub fn description(&self) -> &'static str {
        match self {
            CommandStatus::Ok => "No Error - Operation completed successfully",
            CommandStatus::InvalidMsgLength => "Message Length is invalid",
            CommandStatus::InvalidCommandLength => "Command Length is invalid", 
            CommandStatus::InvalidCommandId => "Invalid Command ID",
            CommandStatus::IncorrectBindStatus => "Incorrect BIND Status for given command",
            CommandStatus::AlreadyBoundState => "ESME Already in Bound State",
            CommandStatus::InvalidPriorityFlag => "Invalid Priority Flag",
            CommandStatus::InvalidRegisteredDeliveryFlag => "Invalid Registered Delivery Flag",
            CommandStatus::SystemError => "System Error",
            CommandStatus::InvalidSourceAddress => "Invalid Source Address",
            CommandStatus::InvalidDestinationAddress => "Invalid Destination Address",
            CommandStatus::InvalidMessageId => "Message ID is invalid",
            CommandStatus::BindFailed => "Bind Failed",
            CommandStatus::InvalidPassword => "Invalid Password",
            CommandStatus::InvalidSystemId => "Invalid System ID",
            CommandStatus::CancelSmFailed => "Cancel SM Failed",
            CommandStatus::ReplacedSmFailed => "Replace SM Failed",
            CommandStatus::MessageQueueFull => "Message Queue Full",
            CommandStatus::InvalidServiceType => "Invalid Service Type",
            CommandStatus::InvalidNumberOfDestinations => "Invalid number of destinations",
            CommandStatus::InvalidDistributionListName => "Invalid Distribution List name",
            CommandStatus::InvalidDestinationFlag => "Destination flag is invalid",
            CommandStatus::InvalidSubmitWithReplaceRequest => "Invalid 'submit with replace' request",
            CommandStatus::InvalidEsmClassFieldData => "Invalid esm_class field data",
            CommandStatus::CannotSubmitToDistributionList => "Cannot Submit to Distribution List",
            CommandStatus::SubmitFailed => "submit_sm or submit_multi failed",
            CommandStatus::InvalidSourceAddressTon => "Invalid Source address TON",
            CommandStatus::InvalidSourceAddressNpi => "Invalid Source address NPI",
            CommandStatus::InvalidDestinationAddressTon => "Invalid Destination address TON",
            CommandStatus::InvalidDestinationAddressNpi => "Invalid Destination address NPI",
            CommandStatus::InvalidSystemTypeField => "Invalid system_type field",
            CommandStatus::InvalidReplaceIfPresentFlag => "Invalid replace_if_present flag",
            CommandStatus::InvalidNumberOfMessages => "Invalid number of messages",
            CommandStatus::ThrottlingError => "Throttling error (ESME has exceeded allowed message limits)",
            CommandStatus::InvalidScheduledDeliveryTime => "Invalid Scheduled Delivery Time",
            CommandStatus::InvalidExpiryTime => "Invalid message validity period (Expiry time)",
            CommandStatus::InvalidPredefinedMessageId => "Predefined Message Invalid or Not Found",
            CommandStatus::ReceiverTemporaryAppError => "ESME Receiver Temporary App Error Code",
            CommandStatus::ReceiverPermanentAppError => "ESME Receiver Permanent App Error Code",
            CommandStatus::ReceiverRejectMessageError => "ESME Receiver Reject Message Error Code",
            CommandStatus::QuerySmRequestFailed => "query_sm request failed",
            CommandStatus::ErrorInOptionalPartofPduBody => "Error in the optional part of the PDU Body",
            CommandStatus::OptionalParameterNotAllowed => "Optional Parameter not allowed",
            CommandStatus::InvalidParameterLength => "Invalid Parameter Length",
            CommandStatus::ExpectedOptionalParameterMissing => "Expected Optional Parameter missing",
            CommandStatus::InvalidOptionalParameterValue => "Invalid Optional Parameter Value",
            CommandStatus::DeliveryFailed => "Delivery Failure",
            CommandStatus::UnknownError => "Unknown Error",
            
            // SMPP v5.0 Error Descriptions
            CommandStatus::InvalidBroadcastAreaIdentifier => "Invalid broadcast area identifier - format invalid or not supported",
            CommandStatus::InvalidBroadcastContentType => "Invalid broadcast content type - not supported or invalid format",
            CommandStatus::InvalidBroadcastFrequency => "Invalid broadcast frequency - outside supported range", 
            CommandStatus::InvalidBroadcastServiceGroup => "Invalid broadcast service group - identifier not recognized",
            CommandStatus::CongestionStateRejected => "Message rejected due to congestion state",
            CommandStatus::MessageThrottled => "Message throttled due to congestion control",
            CommandStatus::InvalidNetworkId => "Invalid network identifier - not recognized or invalid",
            CommandStatus::InvalidNodeId => "Invalid node identifier - not recognized or invalid",
            CommandStatus::UnsupportedVersion => "unsupported SMPP version - version not supported by receiver",
            CommandStatus::VersionMismatch => "Version mismatch detected during negotiation",
        }
    }
    
    /// Check if the operation should be retried for this error code
    pub fn should_retry(&self) -> bool {
        matches!(self,
            CommandStatus::CongestionStateRejected |
            CommandStatus::MessageThrottled |
            CommandStatus::ThrottlingError |
            CommandStatus::MessageQueueFull |
            CommandStatus::SystemError
        )
    }
    
    /// Get suggested retry delay in seconds for retryable errors
    pub fn suggested_retry_delay(&self) -> Option<u32> {
        match self {
            CommandStatus::CongestionStateRejected => Some(30), // 30 seconds for congestion
            CommandStatus::MessageThrottled => Some(60), // 1 minute for throttling
            CommandStatus::ThrottlingError => Some(120), // 2 minutes for legacy throttling
            CommandStatus::MessageQueueFull => Some(10), // 10 seconds for queue full
            CommandStatus::SystemError => Some(5), // 5 seconds for system errors
            _ => None,
        }
    }
    
    /// Get error severity level for logging and monitoring
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            CommandStatus::Ok => ErrorSeverity::Info,
            
            // Critical errors that indicate implementation bugs
            CommandStatus::InvalidCommandId |
            CommandStatus::InvalidCommandLength |
            CommandStatus::InvalidMsgLength => ErrorSeverity::Critical,
            
            // Authentication and authorization errors
            CommandStatus::BindFailed |
            CommandStatus::InvalidPassword |
            CommandStatus::InvalidSystemId |
            CommandStatus::IncorrectBindStatus |
            CommandStatus::AlreadyBoundState => ErrorSeverity::Error,
            
            // Validation errors that indicate client bugs
            CommandStatus::InvalidPriorityFlag |
            CommandStatus::InvalidRegisteredDeliveryFlag |
            CommandStatus::InvalidSourceAddress |
            CommandStatus::InvalidDestinationAddress |
            CommandStatus::InvalidMessageId |
            CommandStatus::InvalidServiceType |
            CommandStatus::InvalidBroadcastAreaIdentifier |
            CommandStatus::InvalidBroadcastContentType |
            CommandStatus::InvalidBroadcastFrequency |
            CommandStatus::InvalidBroadcastServiceGroup |
            CommandStatus::InvalidNetworkId |
            CommandStatus::InvalidNodeId |
            CommandStatus::UnsupportedVersion |
            CommandStatus::VersionMismatch => ErrorSeverity::Error,
            
            // Temporary errors that can be retried
            CommandStatus::SystemError |
            CommandStatus::MessageQueueFull |
            CommandStatus::ThrottlingError |
            CommandStatus::CongestionStateRejected |
            CommandStatus::MessageThrottled => ErrorSeverity::Warning,
            
            // Business logic errors
            CommandStatus::CancelSmFailed |
            CommandStatus::ReplacedSmFailed |
            CommandStatus::SubmitFailed |
            CommandStatus::DeliveryFailed |
            CommandStatus::QuerySmRequestFailed => ErrorSeverity::Warning,
            
            // All other errors default to Error severity
            _ => ErrorSeverity::Error,
        }
    }
    
    /// Get error category for monitoring and alerting
    pub fn category(&self) -> ErrorCategory {
        match self {
            CommandStatus::Ok => ErrorCategory::Success,
            
            CommandStatus::BindFailed |
            CommandStatus::InvalidPassword |
            CommandStatus::InvalidSystemId => ErrorCategory::Authentication,
            
            CommandStatus::IncorrectBindStatus |
            CommandStatus::AlreadyBoundState => ErrorCategory::SessionState,
            
            CommandStatus::ThrottlingError |
            CommandStatus::CongestionStateRejected |
            CommandStatus::MessageThrottled => ErrorCategory::RateLimit,
            
            CommandStatus::InvalidBroadcastAreaIdentifier |
            CommandStatus::InvalidBroadcastContentType |
            CommandStatus::InvalidBroadcastFrequency |
            CommandStatus::InvalidBroadcastServiceGroup => ErrorCategory::Broadcast,
            
            CommandStatus::UnsupportedVersion |
            CommandStatus::VersionMismatch => ErrorCategory::Version,
            
            CommandStatus::InvalidNetworkId |
            CommandStatus::InvalidNodeId => ErrorCategory::Network,
            
            CommandStatus::SystemError |
            CommandStatus::MessageQueueFull => ErrorCategory::System,
            
            CommandStatus::InvalidSourceAddress |
            CommandStatus::InvalidDestinationAddress |
            CommandStatus::InvalidMessageId |
            CommandStatus::InvalidPriorityFlag |
            CommandStatus::InvalidRegisteredDeliveryFlag |
            CommandStatus::InvalidServiceType => ErrorCategory::Validation,
            
            CommandStatus::InvalidCommandId |
            CommandStatus::InvalidCommandLength |
            CommandStatus::InvalidMsgLength => ErrorCategory::Protocol,
            
            _ => ErrorCategory::Business,
        }
    }
    
    /// Get contextual help message for error resolution
    pub fn help_message(&self) -> Option<&'static str> {
        match self {
            CommandStatus::CongestionStateRejected => Some(
                "Network congestion detected. Reduce message rate or implement exponential backoff."
            ),
            CommandStatus::MessageThrottled => Some(
                "Message rate exceeded. Check rate limits and implement proper throttling."
            ),
            CommandStatus::UnsupportedVersion => Some(
                "SMPP version not supported. Check bind PDU interface_version parameter."
            ),
            CommandStatus::VersionMismatch => Some(
                "Version mismatch detected. Ensure client and server use compatible SMPP versions."
            ),
            CommandStatus::InvalidBroadcastAreaIdentifier => Some(
                "Broadcast area identifier format invalid. Check area format specification."
            ),
            CommandStatus::InvalidNetworkId => Some(
                "Network ID not recognized. Verify network identifier configuration."
            ),
            CommandStatus::ThrottlingError => Some(
                "Rate limit exceeded. Implement message throttling or request rate increase."
            ),
            CommandStatus::SystemError => Some(
                "Internal system error. Check server logs and retry after delay."
            ),
            CommandStatus::BindFailed => Some(
                "Authentication failed. Verify system_id, password, and bind parameters."
            ),
            _ => None,
        }
    }
    
    /// Check if error is related to SMPP v5.0 features specifically
    pub fn is_v50_feature_error(&self) -> bool {
        matches!(self,
            CommandStatus::InvalidBroadcastAreaIdentifier |
            CommandStatus::InvalidBroadcastContentType |
            CommandStatus::InvalidBroadcastFrequency |
            CommandStatus::InvalidBroadcastServiceGroup |
            CommandStatus::CongestionStateRejected |
            CommandStatus::MessageThrottled |
            CommandStatus::InvalidNetworkId |
            CommandStatus::InvalidNodeId |
            CommandStatus::UnsupportedVersion |
            CommandStatus::VersionMismatch
        )
    }
}

/// Error severity levels for logging and monitoring
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Informational - successful operations
    Info,
    /// Warning - temporary errors that may be retried
    Warning,
    /// Error - permanent errors requiring intervention
    Error,
    /// Critical - severe errors indicating implementation bugs
    Critical,
}

/// Error categories for monitoring and alerting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Successful operation
    Success,
    /// Authentication and authorization errors
    Authentication,
    /// Session state management errors
    SessionState,
    /// Rate limiting and throttling errors
    RateLimit,
    /// Broadcast messaging specific errors
    Broadcast,
    /// Version negotiation errors
    Version,
    /// Network configuration errors
    Network,
    /// System and infrastructure errors
    System,
    /// Input validation errors
    Validation,
    /// Protocol format errors
    Protocol,
    /// Business logic errors
    Business,
}
