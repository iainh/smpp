// ABOUTME: Defines SMPP v3.4 priority_flag field values per specification Section 4.4.1
// ABOUTME: Implements message priority levels for SMS delivery and network handling

use num_enum::TryFromPrimitive;

/// SMPP v3.4 Priority Flag Field (Section 4.4.1)
///
/// The priority_flag parameter allows the originating SME to assign a priority
/// level to the short message for network handling and delivery. This affects
/// how the SMSC processes and delivers the message.
///
/// ## Field Usage (SMPP v3.4)
/// - **submit_sm.priority_flag**: Message priority for submission (Section 4.4.1)
/// - **deliver_sm.priority_flag**: Message priority for delivery (Section 4.6.1)
///
/// ## Priority Handling
/// Higher priority messages typically receive:
/// - **Faster processing** in SMSC queues
/// - **Priority routing** through network elements  
/// - **Preferred delivery** during network congestion
/// - **Enhanced retry logic** for failed deliveries
///
/// ## Network Technology Mapping
/// Different mobile networks interpret priority levels according to their
/// specific standards and capabilities. The SMSC maps SMPP priority to
/// appropriate network-specific priority mechanisms.
///
/// ## Specification Notes
/// - Priority levels 4-255 are reserved per SMPP v3.4 specification
/// - Default priority is typically Level 0 (normal/non-priority)
/// - Not all networks support all priority levels
/// - Priority handling is implementation-specific per SMSC
///
/// ## References
/// - SMPP v3.4 Specification Section 4.4.1 (submit_sm PDU)
/// - SMPP v3.4 Specification Section 4.6.1 (deliver_sm PDU)
/// - GSM specifications for priority message handling
/// - ANSI-136 and IS-95 priority mechanisms
#[derive(TryFromPrimitive)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PriorityFlag {
    /// Level 0 - Lowest priority (default)
    /// - **GSM**: Non-priority message (normal handling)
    /// - **ANSI-136**: Bulk message (lowest priority queue)
    /// - **IS-95**: Normal priority processing
    /// - **Use case**: Regular promotional/informational messages
    Level0 = 0,

    /// Level 1 - Normal priority
    /// - **GSM**: Priority message (enhanced handling)
    /// - **ANSI-136**: Normal message (standard queue)
    /// - **IS-95**: Interactive priority (faster processing)
    /// - **Use case**: Standard transactional messages, notifications
    Level1 = 1,

    /// Level 2 - High priority  
    /// - **GSM**: Priority message (priority queue)
    /// - **ANSI-136**: Urgent message (high priority queue)
    /// - **IS-95**: Urgent priority (expedited handling)
    /// - **Use case**: Important alerts, time-sensitive notifications
    Level2 = 2,

    /// Level 3 - Highest priority
    /// - **GSM**: Priority message (highest priority queue)
    /// - **ANSI-136**: Very urgent message (critical priority)
    /// - **IS-95**: Emergency priority (immediate processing)
    /// - **Use case**: Emergency alerts, critical system notifications
    Level3 = 3,
    // Note: Priority levels 4-255 are reserved per SMPP v3.4 specification
}
