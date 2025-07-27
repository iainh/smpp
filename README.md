# SMPP v3.4 Protocol Implementation

A high-performance, type-safe Rust implementation of the Short Message Peer-to-Peer (SMPP) protocol version 3.4, as defined in the [SMPP v3.4 Specification](https://smpp.org/SMPP_v3_4_Issue1_2.pdf).

## Overview

This library provides a complete implementation of SMPP v3.4 for building SMS applications, SMS gateways, and mobile network infrastructure. It features zero-allocation parsing, strongly-typed protocol fields, and comprehensive validation according to the SMPP specification.

### Key Features

- **Complete SMPP v3.4 Compliance**: All 26 PDU types implemented per specification sections 4.1-4.12
- **Type Safety**: Strongly-typed fields with compile-time validation
- **High Performance**: Zero-allocation parsing with <200ns PDU processing
- **Async/Await Support**: Built on Tokio for modern Rust async ecosystem
- **Comprehensive Validation**: Protocol-level validation per SMPP specification
- **Consistent API**: Clean, intuitive method naming without unnecessary prefixes
- **Production Ready**: Extensive testing and benchmarking with 210+ test cases

## What's New in Version 0.3.0

This release achieves **100% SMPP v3.4 specification compliance** with significant improvements:

- **Complete PDU Coverage**: All 26 PDU types now implemented including `submit_multi`, `data_sm`, `query_sm`, `cancel_sm`, `replace_sm`, and `alert_notification`
- **Enhanced TLV Support**: Comprehensive support for optional TLV parameters across all PDUs
- **API Consistency**: Removed `get_` prefixes from accessor methods for cleaner, more idiomatic Rust code
- **Improved Documentation**: Fixed macro documentation and enhanced code examples
- **Robust Validation**: Enhanced field validation and error handling throughout the protocol stack
- **Performance Optimizations**: Continued sub-microsecond parsing performance with expanded PDU support

## SMPP v3.4 Specification Compliance

### Implemented PDUs (Section 4 - PDU Definitions)

| PDU Name | Command ID | Spec Section | Status |
|----------|------------|--------------|--------|
| bind_transmitter | 0x00000002 | 4.1.1 | ✅ Complete |
| bind_transmitter_resp | 0x80000002 | 4.1.2 | ✅ Complete |
| bind_receiver | 0x00000001 | 4.2.1 | ✅ Complete |
| bind_receiver_resp | 0x80000001 | 4.2.2 | ✅ Complete |
| bind_transceiver | 0x00000009 | 4.2.5 | ✅ Complete |
| bind_transceiver_resp | 0x80000009 | 4.2.6 | ✅ Complete |
| unbind | 0x00000006 | 4.2.1 | ✅ Complete |
| unbind_resp | 0x80000006 | 4.2.2 | ✅ Complete |
| submit_sm | 0x00000004 | 4.4.1 | ✅ Complete |
| submit_sm_resp | 0x80000004 | 4.4.2 | ✅ Complete |
| submit_multi | 0x00000021 | 4.5.1 | ✅ Complete |
| submit_multi_resp | 0x80000021 | 4.5.2 | ✅ Complete |
| deliver_sm | 0x00000005 | 4.6.1 | ✅ Complete |
| deliver_sm_resp | 0x80000005 | 4.6.2 | ✅ Complete |
| data_sm | 0x00000103 | 4.7.1 | ✅ Complete |
| data_sm_resp | 0x80000103 | 4.7.2 | ✅ Complete |
| query_sm | 0x00000003 | 4.8.1 | ✅ Complete |
| query_sm_resp | 0x80000003 | 4.8.2 | ✅ Complete |
| cancel_sm | 0x00000008 | 4.9.1 | ✅ Complete |
| cancel_sm_resp | 0x80000008 | 4.9.2 | ✅ Complete |
| replace_sm | 0x00000007 | 4.10.1 | ✅ Complete |
| replace_sm_resp | 0x80000007 | 4.10.2 | ✅ Complete |
| enquire_link | 0x00000015 | 4.11.1 | ✅ Complete |
| enquire_link_resp | 0x80000015 | 4.11.2 | ✅ Complete |
| alert_notification | 0x00000102 | 4.12.1 | ✅ Complete |
| generic_nack | 0x80000000 | 4.3.1 | ✅ Complete |
| outbind | 0x0000000B | 4.1.4 | ✅ Complete |

### Protocol Features (Section 5 - Protocol Features)

- **Connection Management**: Full bind/unbind lifecycle per Section 5.1.1
- **Message States**: Complete message state tracking per Section 5.2.28
- **Error Handling**: Comprehensive error codes per Section 5.1.3
- **TLV Parameters**: Full support for optional parameters per Section 5.3
- **Data Coding**: GSM 7-bit, UCS2, and Latin-1 support per Section 5.2.19

### Field Validation (Section 2.2 - SMPP PDU Format)

All fields validated according to SMPP v3.4 specification:
- **Field Length Limits**: Enforced per specification tables
- **Null Termination**: C-Octet String handling per Section 3.1
- **Enumerated Values**: Type-safe enums for all specified values
- **Reserved Fields**: Proper handling of reserved ranges

## Quick Start

### Dependencies

```toml
[dependencies]
smpp = "0.3.0"
tokio = { version = "1.0", features = ["full"] }
```

### Basic SMS Sending Example

```rust
use smpp::client::{ClientBuilder, SmppClient, SmppTransmitter, SmsMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect and bind as transmitter (Section 4.1 - Bind Operations)
    let mut client = ClientBuilder::quick_transmitter(
        "localhost:2775",
        "system_id",
        "password"
    ).await?;

    // Create SMS message
    let sms = SmsMessage::new("1234567890", "0987654321", "Hello, World!");

    // Send SMS message (Section 4.4.1 - submit_sm)
    let message_id = client.send_sms(&sms).await?;

    println!("Message sent with ID: {}", message_id);

    // Clean disconnect (Section 4.2.1 - unbind)
    client.unbind().await?;
    client.disconnect().await?;

    Ok(())
}
```

### Advanced Usage with Message Options

```rust
use smpp::client::{ClientBuilder, SmppClient, SmppTransmitter, SmsMessage};
use smpp::datatypes::{TypeOfNumber, NumericPlanIndicator, PriorityFlag, DataCoding};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect and bind as transmitter
    let mut client = ClientBuilder::quick_transmitter(
        "localhost:2775",
        "system_id", 
        "password"
    ).await?;

    // Create SMS with advanced options
    let sms = SmsMessage::builder()
        .to("1234567890")
        .from("0987654321")
        .text("Hello with options!")
        .priority(PriorityFlag::Level1)
        .data_coding(DataCoding::default())
        .with_delivery_receipt()
        .source_numbering(TypeOfNumber::International, NumericPlanIndicator::Isdn)
        .dest_numbering(TypeOfNumber::International, NumericPlanIndicator::Isdn)
        .build()?;

    // Send message
    let message_id = client.send_sms(&sms).await?;
    println!("Message sent with ID: {}", message_id);

    // Clean disconnect
    client.unbind().await?;
    client.disconnect().await?;

    Ok(())
}
```

## Architecture

### Core Components

The library follows the SMPP v3.4 layered architecture:

```
Application Layer           Your SMS Application
    │
Frame Layer                 smpp::Frame (Section 2.2 - PDU Format)
    │
Connection Layer            smpp::Connection (Section 2.1 - Session Layer)
    │
Transport Layer             TCP/IP (tokio::net::TcpStream)
```

### Key Types

- **`Frame`**: Represents complete SMPP PDUs per Section 2.2
- **`Connection`**: Manages TCP connection with frame buffering
- **Data Types**: Strongly-typed fields matching specification exactly
- **`ToBytes`**: Zero-allocation serialization trait

### Field Types and Specification Mapping

| Rust Type | SMPP Field Type | Spec Reference | Max Length |
|-----------|-----------------|----------------|------------|
| `SystemId` | C-Octet String | Table 4-1 | 16 octets |
| `Password` | C-Octet String | Table 4-1 | 9 octets |
| `ShortMessage` | Octet String | Section 4.4.1 | 254 octets |
| `MessageId` | C-Octet String | Section 4.4.2 | 65 octets |
| `ServiceType` | C-Octet String | Table 4-1 | 6 octets |

## Protocol Flows

### Typical ESME Session (Section 2.1 - Session States)

```
1. TCP Connect          → OPEN state
2. bind_transmitter     → Send bind request (Section 4.1.1)
3. bind_transmitter_resp → Receive bind response (Section 4.1.2)
4. [BOUND_TX state]     → Ready for message submission
5. submit_sm            → Submit message (Section 4.4.1)
6. submit_sm_resp       → Receive message ID (Section 4.4.2)
7. unbind               → Initiate unbind (Section 4.2.1)
8. unbind_resp          → Confirm unbind (Section 4.2.2)
9. TCP Disconnect       → Return to CLOSED state
```

### Message State Transitions (Section 5.2.28)

```
ACCEPTED → ENROUTE → DELIVERED
    ↓         ↓          ↓
REJECTED   UNKNOWN   EXPIRED
```

## Performance

Benchmarked performance on typical hardware:

- **Frame Parsing**: ~200ns for complex PDUs (submit_sm, deliver_sm)
- **Frame Serialization**: ~80ns for complex PDUs
- **Memory Allocation**: Zero allocations for messages under 160 bytes
- **Throughput**: >100K messages/second sustained

See [benchmark.md](benchmark.md) for detailed performance analysis.

## Error Handling

All SMPP v3.4 error codes supported per Section 5.1.3:

```rust
use smpp::datatypes::CommandStatus;

match result {
    Ok(response) => println!("Success: {:?}", response),
    Err(status) => match status {
        CommandStatus::InvalidSourceAddress => {
            // Handle error per Section 5.1.3, Code 0x0000000A
            eprintln!("Invalid source address format");
        },
        CommandStatus::MessageQueueFull => {
            // Handle error per Section 5.1.3, Code 0x00000014
            eprintln!("SMSC message queue full, retry later");
        },
        _ => eprintln!("Other error: {:?}", status),
    }
}
```

## Testing

Run the test suite:

```bash
# Unit tests
cargo test

# Integration tests with real SMSC
cargo test --features integration-tests

# Performance benchmarks
cargo bench

# Check compliance with SMPP specification
cargo test compliance
```

## Development

### Building

```bash
# Standard build
cargo build

# Development build with all features
nix develop  # Enter development shell
cargo build --all-features

# Release build optimized for production
cargo build --release
```

### Code Organization

```
src/
├── lib.rs              # Library entry point
├── frame.rs            # PDU frame parsing (Section 2.2)
├── connection.rs       # Connection management (Section 2.1)
└── datatypes/          # Protocol data types
    ├── mod.rs          # Common types and traits
    ├── submit_sm.rs    # submit_sm PDU (Section 4.4.1)
    ├── deliver_sm.rs   # deliver_sm PDU (Section 4.6.1)
    ├── bind_*.rs       # Bind operations (Section 4.1)
    └── ...
```

## Specification References

This implementation follows the [SMPP v3.4 Specification](https://smpp.org/SMPP_v3_4_Issue1_2.pdf) published by the SMS Forum. Key sections referenced:

- **Section 2**: Protocol Overview and Architecture
- **Section 3**: Data Types and Encoding Rules
- **Section 4**: PDU Definitions and Message Formats
- **Section 5**: Protocol Features and Optional Parameters

For detailed compliance information, see [COMPLIANCE.md](COMPLIANCE.md).

## Contributing

Contributions welcome! Please ensure:

1. **Specification Compliance**: All changes must conform to SMPP v3.4
2. **Performance**: Maintain sub-microsecond parsing performance
3. **Type Safety**: Use strongly-typed fields where possible
4. **Documentation**: Include specification section references

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- SMS Forum for the SMPP v3.4 specification
- Rust async ecosystem (Tokio, Bytes) for high-performance foundations
- Tiger Style methodology for performance-focused development approach
