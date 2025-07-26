// Example: EnquireLink PDU implementation with new codec pattern
//
// This shows how simple PDUs become much cleaner with the codec separation.
// EnquireLink is a good example because it has no body - just the header.

use crate::codec::{CodecError, Decodable, Encodable, PduHeader};
use crate::datatypes::{CommandId, CommandStatus};
use bytes::BytesMut;
use std::io::Cursor;

// These would normally be in src/datatypes/enquire_link.rs
// but shown here for the example

/// enquire_link PDU (Section 4.11.1) - Keep-alive message
///
/// The enquire_link operation is used to provide a confidence check of the
/// communication path between an ESME and an SMSC. On receipt of this request,
/// the recipient should respond with an enquire_link_resp, thus verifying that
/// the application level connection between the ESME and the SMSC is functioning.
#[derive(Clone, Debug, PartialEq)]
pub struct EnquireLink {
    pub command_status: CommandStatus,
    pub sequence_number: u32,
}

/// enquire_link_resp PDU (Section 4.11.2) - Keep-alive response
#[derive(Clone, Debug, PartialEq)]
pub struct EnquireLinkResponse {
    pub command_status: CommandStatus,
    pub sequence_number: u32,
}

// Implementation using new codec traits

impl Decodable for EnquireLink {
    fn command_id() -> CommandId {
        CommandId::EnquireLink
    }

    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        // Validate header
        Self::validate_header(&header)?;

        // enquire_link has no body - just verify we're at the end
        if buf.has_remaining() {
            return Err(CodecError::FieldValidation {
                field: "enquire_link_body",
                reason: "enquire_link PDU should have no body".to_string(),
            });
        }

        Ok(EnquireLink {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
        })
    }
}

impl Encodable for EnquireLink {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Calculate total length (header only)
        let total_length = PduHeader::SIZE as u32;

        // Encode header
        let header = PduHeader {
            command_length: total_length,
            command_id: CommandId::EnquireLink,
            command_status: self.command_status,
            sequence_number: self.sequence_number,
        };
        header.encode(buf);

        // No body to encode
        Ok(())
    }

    fn encoded_size(&self) -> usize {
        PduHeader::SIZE
    }
}

impl Decodable for EnquireLinkResponse {
    fn command_id() -> CommandId {
        CommandId::EnquireLinkResp
    }

    fn decode(header: PduHeader, buf: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        // Validate header
        Self::validate_header(&header)?;

        // enquire_link_resp has no body
        if buf.has_remaining() {
            return Err(CodecError::FieldValidation {
                field: "enquire_link_resp_body",
                reason: "enquire_link_resp PDU should have no body".to_string(),
            });
        }

        Ok(EnquireLinkResponse {
            command_status: header.command_status,
            sequence_number: header.sequence_number,
        })
    }
}

impl Encodable for EnquireLinkResponse {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        // Calculate total length (header only)
        let total_length = PduHeader::SIZE as u32;

        // Encode header
        let header = PduHeader {
            command_length: total_length,
            command_id: CommandId::EnquireLinkResp,
            command_status: self.command_status,
            sequence_number: self.sequence_number,
        };
        header.encode(buf);

        // No body to encode
        Ok(())
    }

    fn encoded_size(&self) -> usize {
        PduHeader::SIZE
    }
}

// Convenience constructors
impl EnquireLink {
    pub fn new(sequence_number: u32) -> Self {
        Self {
            command_status: CommandStatus::Ok,
            sequence_number,
        }
    }
}

impl EnquireLinkResponse {
    pub fn new(sequence_number: u32) -> Self {
        Self {
            command_status: CommandStatus::Ok,
            sequence_number,
        }
    }

    pub fn error(sequence_number: u32, status: CommandStatus) -> Self {
        Self {
            command_status: status,
            sequence_number,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn enquire_link_roundtrip() {
        let original = EnquireLink::new(42);

        // Encode
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Decode
        let mut cursor = Cursor::new(buf.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();
        let decoded = EnquireLink::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn enquire_link_response_roundtrip() {
        let original = EnquireLinkResponse::error(123, CommandStatus::SystemError);

        // Encode
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        // Decode
        let mut cursor = Cursor::new(buf.as_ref());
        let header = PduHeader::decode(&mut cursor).unwrap();
        let decoded = EnquireLinkResponse::decode(header, &mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn enquire_link_size_calculation() {
        let pdu = EnquireLink::new(1);
        assert_eq!(pdu.encoded_size(), 16); // Header only
    }

    #[test]
    fn enquire_link_rejects_body_data() {
        let header = PduHeader {
            command_length: 20, // Claims 4 extra bytes
            command_id: CommandId::EnquireLink,
            command_status: CommandStatus::Ok,
            sequence_number: 1,
        };

        let extra_data = [0x01, 0x02, 0x03, 0x04];
        let mut cursor = Cursor::new(&extra_data[..]);

        let result = EnquireLink::decode(header, &mut cursor);
        assert!(matches!(result, Err(CodecError::FieldValidation { .. })));
    }
}
