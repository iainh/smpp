// ABOUTME: Core SMPP client traits using native async functions for modern Rust implementations
// ABOUTME: Defines extensible interfaces for different SMPP client types and connection management

use crate::client::error::SmppResult;
use crate::client::types::{BindCredentials, SmsMessage};
use crate::datatypes::SubmitSm;
use tokio::net::ToSocketAddrs;

/// Base connection management for SMPP clients
///
/// Provides fundamental connection lifecycle operations that all SMPP
/// clients need regardless of their specific role (transmitter/receiver/transceiver).
pub trait SmppConnection {
    /// Establish connection to SMSC
    ///
    /// Creates a TCP connection to the specified address and initializes
    /// the SMPP protocol buffers for frame-based communication.
    async fn connect<T: ToSocketAddrs>(addr: T) -> SmppResult<Self>
    where
        Self: Sized;

    /// Gracefully disconnect from SMSC
    ///
    /// Closes the TCP connection and cleans up any allocated resources.
    /// Should be called after unbind() for clean session termination.
    async fn disconnect(&mut self) -> SmppResult<()>;

    /// Check if connection is active
    ///
    /// Returns true if the underlying TCP connection is still established.
    fn is_connected(&self) -> bool;
}

/// Core SMPP client operations
///
/// Provides the fundamental SMPP session management operations that are
/// common across all client types. This includes bind/unbind and keep-alive.
pub trait SmppClient: SmppConnection {
    /// Bind to SMSC with specified credentials
    ///
    /// Authenticates with the SMSC using the provided credentials and
    /// establishes an SMPP session of the type specified in bind_type.
    async fn bind(&mut self, credentials: &BindCredentials) -> SmppResult<()>;

    /// Unbind from SMSC
    ///
    /// Terminates the SMPP session gracefully by sending an unbind PDU
    /// and waiting for the response. Connection should be disconnected after.
    async fn unbind(&mut self) -> SmppResult<()>;

    /// Send enquire_link to test connection
    ///
    /// Sends a keep-alive PDU to verify the connection is still active.
    /// Should be called periodically during long sessions.
    async fn enquire_link(&mut self) -> SmppResult<()>;

    /// Get next sequence number for PDU
    ///
    /// Returns the next sequence number to use for outbound PDUs.
    /// Sequence numbers must be unique within a session.
    fn next_sequence_number(&mut self) -> u32;
}

/// SMPP transmitter client operations
///
/// Provides operations for clients that can send SMS messages (submit_sm).
/// Available for transmitter and transceiver bind types.
pub trait SmppTransmitter: SmppClient {
    /// Send SMS message using simplified interface
    ///
    /// Sends an SMS message using the high-level SmsMessage type which
    /// provides sensible defaults for most PDU fields. Returns the message ID
    /// assigned by the SMSC.
    async fn send_sms(&mut self, message: &SmsMessage) -> SmppResult<String>;

    /// Send SMS using full SubmitSm PDU control
    ///
    /// Sends an SMS using a fully constructed SubmitSm PDU, giving complete
    /// control over all fields including optional TLV parameters.
    async fn submit_sm(&mut self, submit: &SubmitSm) -> SmppResult<String>;
}

/// SMPP receiver client operations  
///
/// Provides operations for clients that can receive SMS messages (deliver_sm).
/// Available for receiver and transceiver bind types.
pub trait SmppReceiver: SmppClient {
    /// Wait for incoming deliver_sm PDU
    ///
    /// Blocks until a deliver_sm PDU is received from the SMSC.
    /// Used for receiving SMS messages or delivery receipts.
    async fn receive_message(&mut self) -> SmppResult<crate::datatypes::DeliverSm>;
}

/// SMPP transceiver client operations
///
/// Combines both transmitter and receiver capabilities for clients that
/// need bidirectional SMS communication.
pub trait SmppTransceiver: SmppTransmitter + SmppReceiver {}

// Blanket implementation for any type that implements both transmitter and receiver
impl<T> SmppTransceiver for T where T: SmppTransmitter + SmppReceiver {}
