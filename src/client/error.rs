// ABOUTME: SMPP client error types for comprehensive error handling across all client operations
// ABOUTME: Provides structured error reporting with automatic conversion from underlying I/O and protocol errors

use crate::datatypes::CommandStatus;
use std::io;
use thiserror::Error;

/// Comprehensive error type for SMPP client operations
///
/// Provides structured error handling for all client operations including
/// connection management, protocol operations, and data validation.
#[derive(Debug, Error)]
pub enum SmppError {
    /// I/O error during network operations (connection, read, write)
    #[error("Connection error: {0}")]
    Connection(#[from] io::Error),

    /// SMPP protocol error indicated by command_status field
    #[error("Protocol error: {0:?}")]
    Protocol(CommandStatus),

    /// Data validation error (invalid message length, malformed addresses, etc.)
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Operation timeout
    #[error("Operation timeout")]
    Timeout,

    /// Unexpected PDU received (wrong response type for request)
    #[error("Unexpected PDU: expected {expected}, got {actual}")]
    UnexpectedPdu { expected: String, actual: String },

    /// Connection closed unexpectedly
    #[error("Connection closed unexpectedly")]
    ConnectionClosed,

    /// Client not in correct state for operation
    #[error("Invalid client state: {0}")]
    InvalidState(String),
}

/// Result type alias for SMPP operations
pub type SmppResult<T> = Result<T, SmppError>;

impl From<Box<dyn std::error::Error + Send + Sync>> for SmppError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        if let Some(io_err) = err.downcast_ref::<io::Error>() {
            SmppError::Connection(io::Error::new(io_err.kind(), err.to_string()))
        } else {
            SmppError::InvalidData(err.to_string())
        }
    }
}
