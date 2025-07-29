// ABOUTME: Core SMPP client traits using native async functions for modern Rust implementations
// ABOUTME: Defines extensible interfaces for different SMPP client types and connection management

use crate::client::error::SmppResult;
use crate::client::keepalive::{KeepAliveConfig, KeepAliveStatus};
use crate::client::types::{BindCredentials, SmsMessage, BroadcastMessage};
use crate::datatypes::{SubmitSm, BroadcastSm, QueryBroadcastSm, CancelBroadcastSm, MessageState};
use std::future::Future;
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
    fn connect<T: ToSocketAddrs + Send>(addr: T) -> impl Future<Output = SmppResult<Self>> + Send
    where
        Self: Sized;

    /// Gracefully disconnect from SMSC
    ///
    /// Closes the TCP connection and cleans up any allocated resources.
    /// Should be called after unbind() for clean session termination.
    fn disconnect(&mut self) -> impl Future<Output = SmppResult<()>> + Send;

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
    fn bind(
        &mut self,
        credentials: &BindCredentials,
    ) -> impl Future<Output = SmppResult<()>> + Send;

    /// Unbind from SMSC
    ///
    /// Terminates the SMPP session gracefully by sending an unbind PDU
    /// and waiting for the response. Connection should be disconnected after.
    fn unbind(&mut self) -> impl Future<Output = SmppResult<()>> + Send;

    /// Send enquire_link to test connection
    ///
    /// Sends a keep-alive PDU to verify the connection is still active.
    /// Should be called periodically during long sessions.
    fn enquire_link(&mut self) -> impl Future<Output = SmppResult<()>> + Send;

    /// Start automatic keep-alive with specified configuration
    ///
    /// Initializes the keep-alive system to automatically monitor connection
    /// health using periodic enquire_link PDUs. The client will track timing
    /// and failures, but the application must call `maintain_keep_alive()`
    /// periodically to actually send the PDUs.
    ///
    /// # Arguments
    ///
    /// * `config` - Keep-alive configuration including interval and failure thresholds
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Keep-alive started successfully
    /// * `Err(SmppError::InvalidState)` - Client not connected or already started
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use smpp::client::{DefaultClient, KeepAliveConfig, SmppClient, SmppConnection};
    /// # use std::time::Duration;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = DefaultClient::connect("localhost:2775").await?;
    ///
    /// let config = KeepAliveConfig::new(Duration::from_secs(30))
    ///     .with_max_failures(3);
    /// client.start_keep_alive(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    fn start_keep_alive(
        &mut self,
        config: KeepAliveConfig,
    ) -> impl Future<Output = SmppResult<()>> + Send;

    /// Stop automatic keep-alive
    ///
    /// Disables the keep-alive system and clears any associated state.
    /// No more automatic enquire_link timing will occur, but manual
    /// enquire_link calls will still function.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Keep-alive stopped successfully
    /// * `Err(SmppError)` - Error occurred during shutdown
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use smpp::client::{DefaultClient, SmppClient, SmppConnection};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut client = DefaultClient::connect("localhost:2775").await?;
    /// client.stop_keep_alive().await?;
    /// # Ok(())
    /// # }
    /// ```
    fn stop_keep_alive(&mut self) -> impl Future<Output = SmppResult<()>> + Send;

    /// Get current keep-alive status
    ///
    /// Returns a snapshot of the keep-alive state including whether it's
    /// running, failure counts, and success statistics. Use this to monitor
    /// connection health and troubleshoot issues.
    ///
    /// # Returns
    ///
    /// A `KeepAliveStatus` struct containing current state and statistics.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use smpp::client::{DefaultClient, SmppClient, SmppConnection};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = DefaultClient::connect("localhost:2775").await?;
    /// let status = client.keep_alive_status();
    ///
    /// if status.running {
    ///     println!("Keep-alive active: {}/{} success rate",
    ///              status.total_pongs, status.total_pings);
    ///     
    ///     if status.consecutive_failures > 0 {
    ///         println!("Warning: {} consecutive failures",
    ///                  status.consecutive_failures);
    ///     }
    /// } else {
    ///     println!("Keep-alive is disabled");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    fn keep_alive_status(&self) -> KeepAliveStatus;

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
    fn send_sms(&mut self, message: &SmsMessage)
    -> impl Future<Output = SmppResult<String>> + Send;

    /// Send SMS using full SubmitSm PDU control
    ///
    /// Sends an SMS using a fully constructed SubmitSm PDU, giving complete
    /// control over all fields including optional TLV parameters.
    fn submit_sm(&mut self, submit: &SubmitSm) -> impl Future<Output = SmppResult<String>> + Send;
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
    fn receive_message(
        &mut self,
    ) -> impl Future<Output = SmppResult<crate::datatypes::DeliverSm>> + Send;
}

/// SMPP transceiver client operations
///
/// Combines both transmitter and receiver capabilities for clients that
/// need bidirectional SMS communication.
pub trait SmppTransceiver: SmppTransmitter + SmppReceiver {}

// Blanket implementation for any type that implements both transmitter and receiver
impl<T> SmppTransceiver for T where T: SmppTransmitter + SmppReceiver {}

/// SMPP v5.0 broadcast operations
///
/// Provides operations for clients that support SMPP v5.0 broadcast messaging.
/// Available when connected with interface_version set to SmppV50.
pub trait SmppV50Broadcaster: SmppTransmitter {
    /// Send broadcast message using simplified interface
    ///
    /// Sends a broadcast message using the high-level BroadcastMessage type which
    /// provides sensible defaults for most PDU fields. Returns the message ID
    /// assigned by the SMSC for tracking purposes.
    fn send_broadcast(
        &mut self,
        message: &BroadcastMessage,
    ) -> impl Future<Output = SmppResult<String>> + Send;

    /// Send broadcast using full BroadcastSm PDU control
    ///
    /// Sends a broadcast using a fully constructed BroadcastSm PDU, giving complete
    /// control over all fields including broadcast area identifiers and timing.
    fn broadcast_sm(
        &mut self,
        broadcast: &BroadcastSm,
    ) -> impl Future<Output = SmppResult<String>> + Send;

    /// Query status of a broadcast message
    ///
    /// Queries the current status of a previously submitted broadcast message.
    /// Returns the message state and optional completion time.
    fn query_broadcast(
        &mut self,
        message_id: &str,
        source_addr: &str,
    ) -> impl Future<Output = SmppResult<(MessageState, Option<crate::datatypes::SmppDateTime>)>> + Send;

    /// Query broadcast using full QueryBroadcastSm PDU control
    ///
    /// Queries broadcast status using a fully constructed QueryBroadcastSm PDU,
    /// giving complete control over addressing and search parameters.
    fn query_broadcast_sm(
        &mut self,
        query: &QueryBroadcastSm,
    ) -> impl Future<Output = SmppResult<(MessageState, Option<crate::datatypes::SmppDateTime>)>> + Send;

    /// Cancel a pending broadcast message
    ///
    /// Attempts to cancel a previously submitted broadcast message that is still
    /// pending delivery. Returns success if the message was successfully cancelled.
    fn cancel_broadcast(
        &mut self,
        message_id: &str,
        source_addr: &str,
    ) -> impl Future<Output = SmppResult<()>> + Send;

    /// Cancel broadcast using full CancelBroadcastSm PDU control
    ///
    /// Cancels broadcast using a fully constructed CancelBroadcastSm PDU,
    /// giving complete control over addressing and service type matching.
    fn cancel_broadcast_sm(
        &mut self,
        cancel: &CancelBroadcastSm,
    ) -> impl Future<Output = SmppResult<()>> + Send;
}

/// SMPP v5.0 enhanced client operations
///
/// Provides access to SMPP v5.0 specific features including broadcast messaging,
/// enhanced error handling, and congestion control.
pub trait SmppV50Client: SmppClient + SmppV50Broadcaster {
    /// Check if client is connected with SMPP v5.0
    ///
    /// Returns true if the client bound successfully using InterfaceVersion::SmppV50.
    /// v5.0 features are only available when this returns true.
    fn is_v50_enabled(&self) -> bool;

    /// Get supported SMPP version for this connection
    ///
    /// Returns the interface version that was negotiated during bind.
    /// Use this to determine which features are available.
    fn interface_version(&self) -> crate::datatypes::InterfaceVersion;

    /// Check server congestion state (v5.0 feature)
    ///
    /// Returns the last known congestion state (0-100) reported by the server.
    /// This can be used for adaptive rate limiting. Only available in v5.0.
    fn congestion_state(&self) -> Option<u8>;
}
