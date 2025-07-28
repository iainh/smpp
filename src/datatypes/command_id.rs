// ABOUTME: Defines SMPP v3.4 command identifiers per specification Table 4-1
// ABOUTME: Implements command_id field validation and response bit handling

use num_enum::TryFromPrimitive;

/// SMPP v3.4 Command Identifiers (Table 4-1)
///
/// The command_id field identifies the SMPP PDU type. Per SMPP v3.4 specification
/// Section 2.2.1, this is a 4-octet field in the PDU header.
///
/// ## Command ID Structure
/// - **Bit 31 (MSB)**: Response indicator bit
///   - 0 = Request PDU
///   - 1 = Response PDU  
/// - **Bits 30-0**: Command type identifier
///
/// ## Reserved Ranges (per Table 4-1)
/// - 0x00000000: Reserved
/// - 0x0000000A, 0x0000000C-0x00000014: Reserved  
/// - 0x00000016-0x00000020: Reserved
/// - 0x00000022-0x000000FF: Reserved
/// - 0x00000104-0x0000FFFF: Reserved for SMPP extension
/// - 0x00010200-0x000102FF: Reserved for SMSC vendor specific
///
/// ## References
/// - SMPP v3.4 Specification Section 2.2.1 (PDU Header Format)
/// - SMPP v3.4 Specification Table 4-1 (Command ID Definitions)
#[derive(TryFromPrimitive)]
#[repr(u32)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
pub enum CommandId {
    /// generic_nack PDU (Section 4.3.1) - Error response for invalid PDUs
    GenericNack = 0x8000_0000,

    // Connection Management Operations (Section 4.1)
    /// bind_receiver PDU (Section 4.1.1) - Bind as message receiver
    BindReceiver = 0x0000_0001,
    /// bind_receiver_resp PDU (Section 4.1.2) - Response to bind_receiver
    BindReceiverResp = 0x8000_0001,
    /// bind_transmitter PDU (Section 4.1.1) - Bind as message transmitter  
    BindTransmitter = 0x0000_0002,
    /// bind_transmitter_resp PDU (Section 4.1.2) - Response to bind_transmitter
    BindTransmitterResp = 0x8000_0002,

    // Message Management Operations (Section 4.7-4.9)
    /// query_sm PDU (Section 4.8.1) - Query message status
    QuerySm = 0x0000_0003,
    /// query_sm_resp PDU (Section 4.8.2) - Response to query_sm
    QuerySmResp = 0x8000_0003,

    // Message Submission Operations (Section 4.4)
    /// submit_sm PDU (Section 4.4.1) - Submit short message
    SubmitSm = 0x0000_0004,
    /// submit_sm_resp PDU (Section 4.4.2) - Response to submit_sm
    SubmitSmResp = 0x8000_0004,

    // Message Delivery Operations (Section 4.6)
    /// deliver_sm PDU (Section 4.6.1) - Deliver message to ESME
    DeliverSm = 0x0000_0005,
    /// deliver_sm_resp PDU (Section 4.6.2) - Response to deliver_sm
    DeliverSmResp = 0x8000_0005,

    // Session Management Operations (Section 4.2)
    /// unbind PDU (Section 4.2.1) - Unbind from SMSC
    Unbind = 0x0000_0006,
    /// unbind_resp PDU (Section 4.2.2) - Response to unbind
    UnbindResp = 0x8000_0006,

    // Message Modification Operations (Section 4.9-4.10)
    /// replace_sm PDU (Section 4.9.1) - Replace existing message
    ReplaceSm = 0x0000_0007,
    /// replace_sm_resp PDU (Section 4.9.2) - Response to replace_sm
    ReplaceSmResp = 0x8000_0007,
    /// cancel_sm PDU (Section 4.10.1) - Cancel existing message
    CancelSm = 0x0000_0008,
    /// cancel_sm_resp PDU (Section 4.10.2) - Response to cancel_sm
    CancelSmResp = 0x8000_0008,

    // Transceiver Operations (Section 4.2.5-4.2.6)
    /// bind_transceiver PDU (Section 4.2.5) - Bind as transceiver (TX+RX)
    BindTransceiver = 0x0000_0009,
    /// bind_transceiver_resp PDU (Section 4.2.6) - Response to bind_transceiver
    BindTransceiverResp = 0x8000_0009,

    // Reserved range per Table 4-1
    // 0x0000000A - 0x8000000A: Reserved

    // Network Initiated Operations (Section 4.1.4)
    /// outbind PDU (Section 4.1.4) - SMSC initiated bind request
    Outbind = 0x0000_000B,

    // Reserved ranges per Table 4-1
    // 0x0000000C - 0x00000014: Reserved
    // 0x8000000B - 0x80000014: Reserved

    // Link Management Operations (Section 4.11)
    /// enquire_link PDU (Section 4.11.1) - Link verification request
    EnquireLink = 0x0000_0015,
    /// enquire_link_resp PDU (Section 4.11.2) - Response to enquire_link
    EnquireLinkResp = 0x8000_0015,

    // Reserved ranges per Table 4-1
    // 0x00000016 - 0x00000020: Reserved
    // 0x80000016 - 0x80000020: Reserved

    // Multi-destination Operations (Section 4.5)
    /// submit_multi PDU (Section 4.5.1) - Submit to multiple destinations
    SubmitMulti = 0x0000_0021,
    /// submit_multi_resp PDU (Section 4.5.2) - Response to submit_multi
    SubmitMultiResp = 0x8000_0021,

    // Reserved ranges per Table 4-1
    // 0x00000022 - 0x000000FF: Reserved
    // 0x80000022 - 0x800000FF: Reserved
    // 0x00000100 - 0x80000100: Reserved
    // 0x00000101 - 0x80000101: Reserved

    // Enhanced Messaging Operations (Section 4.12)
    /// alert_notification PDU (Section 4.12.1) - Alert notification
    AlertNotification = 0x0000_0102,
    // 0x80000102: Reserved (no response PDU for alert_notification)
    /// data_sm PDU (Section 4.12.2) - Enhanced data submission
    DataSm = 0x0000_0103,
    /// data_sm_resp PDU (Section 4.12.3) - Response to data_sm
    DataSmResp = 0x8000_0103,

    // SMPP v5.0 Broadcast Operations
    /// broadcast_sm PDU (SMPP v5.0) - Broadcast message to multiple recipients
    BroadcastSm = 0x0000_0111,
    /// broadcast_sm_resp PDU (SMPP v5.0) - Response to broadcast_sm
    BroadcastSmResp = 0x8000_0111,
    /// query_broadcast_sm PDU (SMPP v5.0) - Query broadcast message status
    QueryBroadcastSm = 0x0000_0112,
    /// query_broadcast_sm_resp PDU (SMPP v5.0) - Response to query_broadcast_sm
    QueryBroadcastSmResp = 0x8000_0112,
    /// cancel_broadcast_sm PDU (SMPP v5.0) - Cancel broadcast message
    CancelBroadcastSm = 0x0000_0113,
    /// cancel_broadcast_sm_resp PDU (SMPP v5.0) - Response to cancel_broadcast_sm
    CancelBroadcastSmResp = 0x8000_0113,

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
