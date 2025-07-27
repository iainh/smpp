// ABOUTME: This module provides macros to reduce boilerplate in SMPP PDU implementations
// ABOUTME: Includes macros for header-only PDUs, TLV encoding, and builder patterns

/// Macro for implementing codec traits on header-only PDUs (no body)
/// 
/// This macro generates complete Encodable/Decodable implementations for PDUs
/// that only contain the standard SMPP header with no body content.
/// 
/// # Arguments
/// * `$pdu_type` - The PDU struct name (e.g., EnquireLink)
/// * `$command_id` - The CommandId variant (e.g., CommandId::EnquireLink)
/// 
/// # Generated code
/// - Complete Decodable trait implementation with header validation
/// - Complete Encodable trait implementation for header-only encoding
/// - encoded_size() method returning PduHeader::SIZE
macro_rules! impl_header_only_pdu {
    ($pdu_type:ident, $command_id:expr) => {
        impl $crate::codec::Decodable for $pdu_type {
            fn command_id() -> $crate::datatypes::CommandId {
                $command_id
            }

            fn decode(
                header: $crate::codec::PduHeader,
                buf: &mut std::io::Cursor<&[u8]>,
            ) -> Result<Self, $crate::codec::CodecError> {
                use bytes::Buf;
                
                // Validate header
                Self::validate_header(&header)?;

                // Header-only PDUs should have no body
                if buf.has_remaining() {
                    return Err($crate::codec::CodecError::FieldValidation {
                        field: concat!(stringify!($pdu_type), "_body"),
                        reason: concat!(
                            stringify!($pdu_type),
                            " PDU should have no body"
                        ).to_string(),
                    });
                }

                Ok($pdu_type {
                    command_status: header.command_status,
                    sequence_number: header.sequence_number,
                })
            }
        }

        impl $crate::codec::Encodable for $pdu_type {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::codec::CodecError> {
                // Calculate total length (header only)
                let total_length = $crate::codec::PduHeader::SIZE as u32;

                // Encode header
                let header = $crate::codec::PduHeader {
                    command_length: total_length,
                    command_id: $command_id,
                    command_status: self.command_status,
                    sequence_number: self.sequence_number,
                };
                header.encode(buf)?;

                // No body to encode
                Ok(())
            }

            fn encoded_size(&self) -> usize {
                $crate::codec::PduHeader::SIZE
            }
        }
    };
}

/// Macro for encoding multiple optional TLV fields in batch
/// 
/// This macro generates code to encode all specified optional TLV fields,
/// checking if each is Some() and encoding it if present.
/// 
/// # Arguments
/// * `$self_expr` - Expression referring to self (e.g., self)
/// * `$buf_expr` - Expression for the buffer to encode into
/// * `$($field:ident),*` - Comma-separated list of field names
/// 
/// # Generated code
/// For each field, generates:
/// ```rust
/// if let Some(ref tlv) = $self_expr.$field {
///     tlv.encode($buf_expr)?;
/// }
/// ```
macro_rules! encode_optional_tlvs {
    ($self_expr:expr, $buf_expr:expr, $($field:ident),* $(,)?) => {
        $(
            if let Some(ref tlv) = $self_expr.$field {
                tlv.encode($buf_expr)?;
            }
        )*
    };
}

/// Macro for calculating encoded size of multiple optional TLV fields
/// 
/// This macro generates code to calculate the total encoded size of all
/// specified optional TLV fields, adding their sizes if present.
/// 
/// # Arguments
/// * `$size_expr` - Mutable expression for accumulating size
/// * `$self_expr` - Expression referring to self
/// * `$($field:ident),*` - Comma-separated list of field names
/// 
/// # Generated code
/// For each field, generates:
/// ```rust
/// if let Some(ref tlv) = $self_expr.$field {
///     $size_expr += tlv.encoded_size();
/// }
/// ```
macro_rules! size_optional_tlvs {
    ($size_expr:expr, $self_expr:expr, $($field:ident),* $(,)?) => {
        $(
            if let Some(ref tlv) = $self_expr.$field {
                $size_expr += tlv.encoded_size();
            }
        )*
    };
}

/// Macro for generating builder setter methods
/// 
/// This macro generates fluent setter methods for builder patterns,
/// where each method takes a value, sets the corresponding field,
/// and returns self for method chaining.
/// 
/// # Arguments
/// * `$($field:ident: $type:ty),*` - Field name and type pairs
/// 
/// # Generated code
/// For each field, generates:
/// ```rust
/// pub fn $field(mut self, $field: $type) -> Self {
///     self.$field = $field;
///     self
/// }
/// ```
macro_rules! builder_setters {
    ($($field:ident: $type:ty),* $(,)?) => {
        $(
            pub fn $field(mut self, $field: $type) -> Self {
                self.$field = $field;
                self
            }
        )*
    };
}

/// Macro for generating constructor methods for header-only PDUs
/// 
/// This macro generates common constructor patterns for PDUs that only
/// contain a header with command_status and sequence_number fields.
/// 
/// # Arguments
/// * `$pdu_type` - The PDU struct name
/// 
/// # Generated code
/// - `new(sequence_number: u32)` - Creates PDU with Ok status
/// - `error(sequence_number: u32, status: CommandStatus)` - Creates PDU with error status
macro_rules! impl_header_only_constructors {
    ($pdu_type:ident) => {
        impl $pdu_type {
            /// Create a new PDU with Ok status
            pub fn new(sequence_number: u32) -> Self {
                Self {
                    command_status: $crate::datatypes::CommandStatus::Ok,
                    sequence_number,
                }
            }

            /// Create a PDU with error status
            pub fn error(sequence_number: u32, status: $crate::datatypes::CommandStatus) -> Self {
                Self {
                    command_status: status,
                    sequence_number,
                }
            }
        }
    };
}

/// Macro for implementing the complete header-only PDU pattern
/// 
/// This is a convenience macro that combines codec implementation and
/// constructor generation for header-only PDUs.
/// 
/// # Arguments
/// * `$pdu_type` - The PDU struct name
/// * `$command_id` - The CommandId variant
/// 
/// # Generated code
/// - Complete Encodable/Decodable trait implementations
/// - Constructor methods (new, error)
macro_rules! impl_complete_header_only_pdu {
    ($pdu_type:ident, $command_id:expr) => {
        $crate::macros::impl_header_only_pdu!($pdu_type, $command_id);
        $crate::macros::impl_header_only_constructors!($pdu_type);
    };
}


// Make macros available to the rest of the crate
pub(crate) use {
    builder_setters, 
    encode_optional_tlvs, 
    impl_complete_header_only_pdu,
    impl_header_only_constructors,
    impl_header_only_pdu, 
    size_optional_tlvs
};