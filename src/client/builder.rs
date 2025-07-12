// ABOUTME: Client factory and builder patterns for easy SMPP client creation
// ABOUTME: Provides convenient constructors for different types of SMPP clients with trait objects

use crate::client::default::DefaultClient;
use crate::client::error::SmppResult;
use crate::client::traits::{SmppClient, SmppConnection, SmppTransmitter};
use crate::client::types::BindCredentials;
use tokio::net::ToSocketAddrs;

/// Factory for creating different types of SMPP clients
///
/// Provides convenient methods for creating clients with specific capabilities
/// (transmitter, receiver, transceiver) and handles the connection + bind process.
pub struct ClientBuilder;

impl ClientBuilder {
    /// Create a transmitter client (can send SMS)
    ///
    /// Establishes connection and binds as transmitter in a single operation.
    /// Returns a trait object that can be used for sending SMS messages.
    pub async fn transmitter<T: ToSocketAddrs + Send>(
        addr: T,
        credentials: BindCredentials,
    ) -> SmppResult<impl SmppTransmitter> {
        let mut client = DefaultClient::connect(addr).await?;
        client.bind(&credentials).await?;
        Ok(client)
    }

    /// Create a basic client (connection + bind only)
    ///
    /// Establishes connection and binds with specified credentials.
    /// Use this when you need a client but don't know the specific type at compile time.
    pub async fn client<T: ToSocketAddrs + Send>(
        addr: T,
        credentials: BindCredentials,
    ) -> SmppResult<impl SmppClient> {
        let mut client = DefaultClient::connect(addr).await?;
        client.bind(&credentials).await?;
        Ok(client)
    }

    /// Create a connection without binding
    ///
    /// Just establishes the TCP connection. You must call bind() separately.
    /// Useful when you need to control the binding process manually.
    pub async fn connection<T: ToSocketAddrs + Send>(addr: T) -> SmppResult<impl SmppConnection> {
        DefaultClient::connect(addr).await
    }
}

/// Convenience functions for quick client creation
impl ClientBuilder {
    /// Quick transmitter creation with minimal parameters
    ///
    /// Creates a transmitter client with default settings.
    /// Equivalent to `transmitter(addr, BindCredentials::transmitter(system_id, password))`.
    pub async fn quick_transmitter<T: ToSocketAddrs + Send>(
        addr: T,
        system_id: impl Into<String>,
        password: impl Into<String>,
    ) -> SmppResult<impl SmppTransmitter> {
        let credentials = BindCredentials::transmitter(system_id, password);
        Self::transmitter(addr, credentials).await
    }

    /// Quick client creation with minimal parameters
    ///
    /// Creates a client bound as transmitter with default settings.
    /// Use this for simple SMS sending scenarios.
    pub async fn quick_client<T: ToSocketAddrs + Send>(
        addr: T,
        system_id: impl Into<String>,
        password: impl Into<String>,
    ) -> SmppResult<impl SmppClient> {
        let credentials = BindCredentials::transmitter(system_id, password);
        Self::client(addr, credentials).await
    }
}

/// Builder pattern for more complex client configuration
///
/// Use this when you need to configure connection options, timeouts,
/// or other advanced settings before creating the client.
#[derive(Debug, Default)]
pub struct ClientOptions {
    // Future: connection timeout, retry settings, etc.
    _placeholder: (),
}

impl ClientOptions {
    /// Create new client options with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a transmitter client with these options
    ///
    /// Future extension point for advanced connection configuration.
    pub async fn build_transmitter<T: ToSocketAddrs + Send>(
        self,
        addr: T,
        credentials: BindCredentials,
    ) -> SmppResult<impl SmppTransmitter> {
        // For now, just delegate to ClientBuilder
        // Future: apply connection options here
        ClientBuilder::transmitter(addr, credentials).await
    }

    /// Build a client with these options
    pub async fn build_client<T: ToSocketAddrs + Send>(
        self,
        addr: T,
        credentials: BindCredentials,
    ) -> SmppResult<impl SmppClient> {
        // For now, just delegate to ClientBuilder
        // Future: apply connection options here
        ClientBuilder::client(addr, credentials).await
    }
}
