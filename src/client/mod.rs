// ABOUTME: SMPP client module providing trait-based interfaces for extensible client implementations
// ABOUTME: Exports all client components including traits, builders, error types, and default implementation

//! SMPP Client Module
//!
//! This module provides a trait-based SMPP client implementation with the following features:
//!
//! * **Native async traits** - Uses Rust 1.75+ async fn in traits (no async_trait dependency)
//! * **Layered design** - Separate traits for connection, client, and specific operations
//! * **Type safety** - Different traits for transmitter/receiver/transceiver capabilities
//! * **Builder patterns** - Easy client creation with sensible defaults
//! * **Keep-alive support** - Automatic connection health monitoring
//! * **Extensible** - Implement traits for custom client behavior
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use smpp::client::{ClientBuilder, SmsMessage, SmppClient, SmppConnection, SmppTransmitter};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a transmitter client
//! let mut client = ClientBuilder::quick_transmitter(
//!     "localhost:2775",
//!     "system_id",
//!     "password"
//! ).await?;
//!
//! // Send an SMS
//! let message = SmsMessage::new("123456789", "987654321", "Hello!");
//! let message_id = client.send_sms(&message).await?;
//!
//! // Clean shutdown
//! client.unbind().await?;
//! client.disconnect().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## SMPP v5.0 Broadcast Messaging
//!
//! For clients that support SMPP v5.0, broadcast messaging is available:
//!
//! ```rust,no_run
//! use smpp::client::{ClientBuilder, BroadcastMessage, SmppV50Client, SmppV50Broadcaster};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a v5.0 transmitter client
//! let mut client = ClientBuilder::quick_transmitter_v50(
//!     "localhost:2775",
//!     "system_id",
//!     "password"
//! ).await?;
//!
//! // Send a broadcast message
//! let broadcast = BroadcastMessage::new(
//!     "1234567890",
//!     "BC001",
//!     vec![0x01, 0x02, 0x03, 0x04], // area identifier
//! );
//! let message_id = client.send_broadcast(&broadcast).await?;
//!
//! // Query broadcast status
//! let (state, final_date) = client.query_broadcast(&message_id, "1234567890").await?;
//!
//! // Cancel if needed
//! client.cancel_broadcast(&message_id, "1234567890").await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Keep-Alive for Long-Running Applications
//!
//! For applications that maintain SMPP connections for extended periods,
//! use the keep-alive functionality to automatically monitor connection health:
//!
//! ```rust,no_run
//! use smpp::client::{DefaultClient, KeepAliveConfig, SmppClient, SmppConnection};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create and connect client
//! let mut client = DefaultClient::connect("localhost:2775").await?;
//!
//! // Configure keep-alive (30s interval, 3 max failures)
//! let config = KeepAliveConfig::new(Duration::from_secs(30))
//!     .with_max_failures(3);
//! client.start_keep_alive(config).await?;
//!
//! loop {
//!     // Your application logic here
//!     
//!     // Maintain connection health
//!     client.maintain_keep_alive().await?;
//!     
//!     // Check for connection failure
//!     if client.is_keep_alive_failed() {
//!         println!("Connection failed, need to reconnect");
//!         break;
//!     }
//!     
//!     tokio::time::sleep(Duration::from_secs(5)).await;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! The client module uses a layered trait design:
//!
//! * `SmppConnection` - Basic TCP connection management
//! * `SmppClient` - Core SMPP operations (bind, unbind, enquire_link)
//! * `SmppTransmitter` - SMS sending operations (extends SmppClient)
//! * `SmppReceiver` - SMS receiving operations (extends SmppClient)  
//! * `SmppTransceiver` - Combined TX/RX operations (extends both)
//! * `SmppV50Broadcaster` - SMPP v5.0 broadcast operations (extends SmppTransmitter)
//! * `SmppV50Client` - SMPP v5.0 enhanced client (extends SmppClient + SmppV50Broadcaster)
//!
//! ## Builder Patterns
//!
//! Use `ClientBuilder` for most scenarios:
//!
//! ```rust,no_run
//! # use smpp::client::{ClientBuilder, BindCredentials};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Full control over bind credentials
//! let credentials = BindCredentials::transmitter("system_id", "password")
//!     .with_system_type("MYAPP");
//! let client = ClientBuilder::transmitter("localhost:2775", credentials).await?;
//!
//! // Quick creation for simple cases
//! let client = ClientBuilder::quick_transmitter("localhost:2775", "id", "pass").await?;
//! # Ok(())
//! # }
//! ```

pub mod builder;
pub mod default;
pub mod error;
pub mod keepalive;
pub mod traits;
pub mod types;

// Re-export the main types for easy access
pub use builder::{ClientBuilder, ClientOptions};
pub use default::DefaultClient;
pub use error::{SmppError, SmppResult};
pub use keepalive::{KeepAliveConfig, KeepAliveManager, KeepAliveStatus};
pub use traits::{
    SmppClient, SmppConnection, SmppReceiver, SmppTransceiver, SmppTransmitter,
    SmppV50Broadcaster, SmppV50Client,
};
pub use types::{
    BindCredentials, BindType, SmsMessage, SmsMessageBuilder, SmsOptions,
    BroadcastMessage, BroadcastMessageBuilder, BroadcastOptions,
};

// For backwards compatibility, also export a simple connect function
pub use builder::ClientBuilder as Client;
