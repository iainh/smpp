# SMPP Protocol Implementation

A high-performance, type-safe Rust implementation of the Short Message Peer-to-Peer (SMPP) protocol supporting both versions 3.4 and 5.0.

## Overview

This library provides complete implementations of SMPP v3.4 and v5.0 for building SMS applications, SMS gateways, and mobile network infrastructure. It features zero-allocation parsing, strongly-typed protocol fields, and comprehensive validation according to both SMPP specifications.

### Key Features

- **Dual Version Support**: Complete SMPP v3.4 and v5.0 implementations
- **Type Safety**: Strongly-typed fields with compile-time validation
- **High Performance**: Zero-allocation parsing with <200ns PDU processing
- **Async/Await Support**: Built on Tokio for modern Rust async ecosystem
- **Comprehensive Validation**: Protocol-level validation per SMPP specifications
- **Consistent API**: Clean, intuitive method naming without unnecessary prefixes
- **Production Ready**: Extensive testing and benchmarking with 300+ test cases

## SMPP Version Support

This library supports both SMPP v3.4 and v5.0 protocols:

- **SMPP v3.4**: Complete implementation with all 26 PDU types
- **SMPP v5.0**: Enhanced implementation with broadcast messaging, flow control, and improved error handling

The client API automatically detects and negotiates the appropriate protocol version based on the server capabilities.

## What's New in Version 0.4.0

This release adds **complete SMPP v5.0 support** alongside the existing v3.4 implementation:

- **Dual Version Support**: Complete SMPP v3.4 and v5.0 implementations with automatic version negotiation
- **SMPP v5.0 Features**: Broadcast messaging, enhanced flow control, and improved error handling
- **Broadcast PDUs**: Full support for `broadcast_sm`, `cancel_broadcast_sm`, and `query_broadcast_sm`
- **Flow Control**: Adaptive rate limiting and congestion management for high-throughput scenarios
- **Enhanced Client API**: Unified client interface supporting both protocol versions seamlessly
- **Extended Testing**: 300+ test cases covering both v3.4 and v5.0 protocol features

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
smpp = "0.4.0"
tokio = { version = "1.0", features = ["full"] }
```

### Basic SMS Sending (SMPP v3.4)

```rust
use smpp::client::{ClientBuilder, SmppClient, SmppTransmitter, SmsMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect and bind as transmitter
    let mut client = ClientBuilder::quick_transmitter(
        "localhost:2775",
        "system_id",
        "password"
    ).await?;

    // Create SMS message
    let sms = SmsMessage::new("1234567890", "0987654321", "Hello, World!");

    // Send SMS message
    let message_id = client.send_sms(&sms).await?;
    println!("Message sent with ID: {}", message_id);

    // Clean disconnect
    client.unbind().await?;
    client.disconnect().await?;

    Ok(())
}
```

### SMPP v5.0 with Flow Control

```rust
use smpp::client::{ClientBuilder, SmppClient, SmppTransmitter, SmsMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect with SMPP v5.0 flow control enabled
    let mut client = ClientBuilder::new()
        .address("localhost:2775")
        .credentials("system_id", "password")
        .enable_flow_control(true)
        .max_rate_per_second(100)  // Rate limiting
        .build_transmitter()
        .await?;

    // Send message with automatic flow control
    let sms = SmsMessage::new("1234567890", "0987654321", "Hello from SMPP v5.0!");
    let message_id = client.send_sms(&sms).await?;
    println!("Message sent with ID: {}", message_id);

    client.unbind().await?;
    client.disconnect().await?;

    Ok(())
}
```

### Broadcast Messaging (SMPP v5.0)

```rust
use smpp::client::{ClientBuilder, SmppClient, SmppTransceiver};
use smpp::datatypes::{BroadcastSm, BroadcastAreaIdentifier};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect as transceiver for broadcast operations
    let mut client = ClientBuilder::quick_transceiver(
        "localhost:2775",
        "system_id",
        "password"
    ).await?;

    // Create broadcast message
    let broadcast = BroadcastSm::builder()
        .service_type("BCAST")
        .source_address("12345")
        .message_text("Emergency Alert: Severe weather warning in your area")
        .broadcast_areas(vec![
            BroadcastAreaIdentifier::cell_id(12345),
            BroadcastAreaIdentifier::location_area(67890),
        ])
        .build()?;

    // Send broadcast message
    let message_id = client.send_broadcast(&broadcast).await?;
    println!("Broadcast sent with ID: {}", message_id);

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

The library follows the SMPP layered architecture for both v3.4 and v5.0:

```
Application Layer           Your SMS Application
    │
Client Layer                smpp::client (Version negotiation & flow control)
    │
Frame Layer                 smpp::Frame (PDU format for both versions)
    │
Connection Layer            smpp::Connection (Session management)
    │
Transport Layer             TCP/IP (tokio::net::TcpStream)
```

### Key Types

- **`Frame`**: Represents complete SMPP PDUs for both v3.4 and v5.0
- **`Connection`**: Manages TCP connection with frame buffering
- **`SmppClient`**: High-level client API with version negotiation
- **Data Types**: Strongly-typed fields matching both specifications
- **`ToBytes`**: Zero-allocation serialization trait

### Version-Specific Features

**SMPP v3.4:**
- 26 standard PDU types
- Basic message submission and delivery
- Standard error handling and validation

**SMPP v5.0:**
- All v3.4 features plus:
- Broadcast messaging (broadcast_sm, cancel_broadcast_sm, query_broadcast_sm)
- Enhanced flow control with rate limiting
- Improved error handling and diagnostics
- Extended TLV parameter support

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

This implementation follows both SMPP specifications published by the SMS Forum:

- **[SMPP v3.4 Specification](https://smpp.org/SMPP_v3_4_Issue1_2.pdf)**: Complete implementation with all required PDUs
- **[SMPP v5.0 Specification](https://smpp.org/SMPP_v5_0.pdf)**: Enhanced features including broadcast messaging and flow control

Key sections referenced:
- **Section 2**: Protocol Overview and Architecture
- **Section 3**: Data Types and Encoding Rules  
- **Section 4**: PDU Definitions and Message Formats
- **Section 5**: Protocol Features and Optional Parameters

For detailed compliance information, see [COMPLIANCE.md](COMPLIANCE.md).

## Contributing

Contributions welcome! Please ensure:

1. **Specification Compliance**: All changes must conform to SMPP v3.4 and/or v5.0 specifications
2. **Performance**: Maintain sub-microsecond parsing performance
3. **Type Safety**: Use strongly-typed fields where possible
4. **Documentation**: Include specification section references

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- SMS Forum for the SMPP v3.4 specification
- Rust async ecosystem (Tokio, Bytes) for high-performance foundations
- Tiger Style methodology for performance-focused development approach
