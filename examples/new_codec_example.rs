// Example demonstrating the new codec architecture
//
// This shows how the separated codec makes PDU handling much cleaner
// and more extensible.

use smpp::codec::{CodecError, Encodable, Frame, PduRegistry};
use smpp::datatypes::{CommandStatus, EnquireLink, EnquireLinkResponse};
use std::io::Cursor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("SMPP Codec Architecture Demo");
    println!("============================");

    // 1. Create PDUs using the new constructors
    let enquire_link = EnquireLink::new(42);
    let enquire_response = EnquireLinkResponse::error(42, CommandStatus::SystemError);

    println!("Created PDUs:");
    println!("  EnquireLink: seq={}", enquire_link.sequence_number);
    println!(
        "  EnquireLinkResponse: seq={}, status={:?}",
        enquire_response.sequence_number, enquire_response.command_status
    );

    // 2. Encode PDUs using the new trait
    let link_bytes = enquire_link.to_bytes()?;
    let response_bytes = enquire_response.to_bytes()?;

    println!("\nEncoded sizes:");
    println!("  EnquireLink: {} bytes", link_bytes.len());
    println!("  EnquireLinkResponse: {} bytes", response_bytes.len());

    // 3. Decode using the registry
    let registry = PduRegistry::new();

    // Decode enquire_link
    let mut cursor = Cursor::new(link_bytes.as_ref());
    let header = smpp::codec::PduHeader::decode(&mut cursor)?;
    let frame = registry.decode_pdu(header, &mut cursor)?;

    match frame {
        Frame::EnquireLink(pdu) => {
            println!("\nDecoded EnquireLink: seq={}", pdu.sequence_number);
        }
        _ => println!("Unexpected frame type"),
    }

    // Decode enquire_link_resp
    let mut cursor = Cursor::new(response_bytes.as_ref());
    let header = smpp::codec::PduHeader::decode(&mut cursor)?;
    let frame = registry.decode_pdu(header, &mut cursor)?;

    match frame {
        Frame::EnquireLinkResp(pdu) => {
            println!(
                "Decoded EnquireLinkResponse: seq={}, status={:?}",
                pdu.sequence_number, pdu.command_status
            );
        }
        _ => println!("Unexpected frame type"),
    }

    // 4. Show the advantages of the new codec
    println!("\nCodec Architecture Benefits:");
    println!("✓ Clean separation of encoding/decoding logic");
    println!("✓ Each PDU implements Encodable/Decodable traits");
    println!("✓ Registry-based dispatch for extensibility");
    println!("✓ Forward compatibility with unknown PDUs");
    println!("✓ No more giant match statements for encoding");
    println!("✓ Better error handling with structured CodecError");

    // 5. Demonstrate error handling
    println!("\nError Handling Demo:");

    // Try to decode invalid data
    let invalid_data = [0x00, 0x00, 0x00, 0x08]; // Invalid command_length
    let mut cursor = Cursor::new(&invalid_data[..]);

    match smpp::codec::PduHeader::decode(&mut cursor) {
        Err(CodecError::InvalidPduLength { length, min, max }) => {
            println!(
                "✓ Caught invalid PDU length: {} (valid range: {}-{})",
                length, min, max
            );
        }
        _ => println!("Unexpected result"),
    }

    println!("\nDemo completed successfully!");
    Ok(())
}
