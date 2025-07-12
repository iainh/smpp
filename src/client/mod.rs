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
//! * **Extensible** - Implement traits for custom client behavior
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use smpp::client::{ClientBuilder, SmsMessage};
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
//! ## Architecture
//!
//! The client module uses a layered trait design:
//!
//! * `SmppConnection` - Basic TCP connection management
//! * `SmppClient` - Core SMPP operations (bind, unbind, enquire_link)
//! * `SmppTransmitter` - SMS sending operations (extends SmppClient)
//! * `SmppReceiver` - SMS receiving operations (extends SmppClient)  
//! * `SmppTransceiver` - Combined TX/RX operations (extends both)
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
pub mod traits;
pub mod types;

// Re-export the main types for easy access
pub use builder::{ClientBuilder, ClientOptions};
pub use default::DefaultClient;
pub use error::{SmppError, SmppResult};
pub use traits::{SmppClient, SmppConnection, SmppReceiver, SmppTransceiver, SmppTransmitter};
pub use types::{BindCredentials, BindType, SmsMessage, SmsMessageBuilder, SmsOptions};

// For backwards compatibility, also export a simple connect function
pub use builder::ClientBuilder as Client;
