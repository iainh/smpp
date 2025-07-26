//! SMPP v3.4 Protocol Frame Implementation
//!
//! This module re-exports the Frame enum and parsing functionality from the codec module.
//! The frame implementation has been moved to a modern codec-based architecture.

// Re-export the Frame enum and related types from codec
pub use crate::codec::{CodecError, Frame, PduRegistry};

/// Legacy error type for backward compatibility
#[derive(Debug)]
pub enum Error {
    /// Not enough data is available to parse a message
    Incomplete,
    /// Invalid message encoding
    Other(crate::Error),
}

impl From<CodecError> for Error {
    fn from(err: CodecError) -> Self {
        match err {
            CodecError::Incomplete => Error::Incomplete,
            _ => Error::Other(Box::new(err)),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Incomplete => write!(f, "Incomplete frame"),
            Error::Other(err) => write!(f, "Frame error: {err}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Other(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}
