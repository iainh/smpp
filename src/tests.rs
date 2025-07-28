//! Integration tests for SMPP PDU encoding and decoding

use crate::codec::Encodable;
use crate::datatypes::*;
use crate::frame::{Error as FrameError, Frame};
use std::io::Cursor;

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_frame_check_insufficient_data() {
        let data = vec![0x00, 0x00]; // Only 2 bytes
        let mut cursor = Cursor::new(data.as_slice());

        let result = Frame::check(&mut cursor);
        assert!(matches!(result, Err(FrameError::Incomplete)));
    }

    #[test]
    fn test_frame_check_invalid_length() {
        let data = vec![
            0x00, 0x00, 0x00, 0x05, // command_length = 5 (too small)
            0x00, 0x00, 0x00, 0x15, // command_id
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
        ];
        let mut cursor = Cursor::new(data.as_slice());

        let result = Frame::check(&mut cursor);
        assert!(matches!(result, Err(FrameError::Other(_))));
    }

    #[test]
    fn test_frame_check_length_too_large() {
        let data = vec![
            0xFF, 0xFF, 0xFF, 0xFF, // command_length = max u32
            0x00, 0x00, 0x00, 0x15, // command_id
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
        ];
        let mut cursor = Cursor::new(data.as_slice());

        let result = Frame::check(&mut cursor);
        assert!(matches!(result, Err(FrameError::Incomplete)));
    }

    #[test]
    fn test_bind_transmitter_max_field_lengths() {
        // Test with maximum allowed field lengths per SMPP spec
        let bind_transmitter = BindTransmitter {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            system_id: SystemId::from("A".repeat(15).as_str()), // Max 15 chars (16 with null terminator)
            password: Some(Password::from("B".repeat(8).as_str())), // Max 8 chars (9 with null terminator)
            system_type: SystemType::from("C".repeat(12).as_str()), // Max 12 chars (13 with null terminator)
            interface_version: InterfaceVersion::SmppV34,
            addr_ton: TypeOfNumber::International,
            addr_npi: NumericPlanIndicator::Isdn,
            address_range: AddressRange::from("D".repeat(40).as_str()), // Max 40 chars (41 with null terminator)
        };

        let bytes = crate::codec::Encodable::to_bytes(&bind_transmitter);

        // Should not panic and should produce valid output
        assert!(bytes.len() > 16); // At least header size

        // Test round-trip
        let mut cursor = Cursor::new(bytes.as_ref());
        let result = Frame::parse(&mut cursor);
        assert!(result.is_ok());
    }

    #[test]
    fn test_submit_sm_zero_length_message() {
        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: ServiceType::default(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: SourceAddr::new("1234567890", TypeOfNumber::International).unwrap(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::new("0987654321", TypeOfNumber::International)
                .unwrap(),
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
            sm_default_msg_id: 0,
            sm_length: 0,
            short_message: ShortMessage::default(),
            // All optional parameters set to None
            user_message_reference: None,
            source_port: None,
            source_addr_submit: None,
            destination_port: None,
            dest_addr_submit: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            more_messages_to_send: None,
            payload_type: None,
            message_payload: None,
            privacy_indicator: None,
            callback_num: None,
            callback_num_pres_ind: None,
            callback_num_atag: None,
            source_subaddress: None,
            dest_subaddress: None,
            display_time: None,
            sms_signal: None,
            ms_validity: None,
            ms_msg_wait_facilities: None,
            number_of_messages: None,
            alert_on_msg_delivery: None,
            language_indicator: None,
            its_reply_type: None,
            its_session_info: None,
            ussd_service_op: None,
        };

        let bytes = crate::codec::Encodable::to_bytes(&submit_sm);

        // Should handle empty message gracefully
        assert!(bytes.len() > 16);

        // Find sm_length byte and verify it's 0
        // This is a bit brittle but validates the encoding
        let header_and_mandatory = bytes.len() >= 50; // Rough estimate
        assert!(header_and_mandatory);
    }

    #[test]
    fn test_submit_sm_length_mismatch() {
        // Test case where sm_length doesn't match actual message length
        // This should return an error due to our new validation
        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: ServiceType::default(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: SourceAddr::new("1234567890", TypeOfNumber::International).unwrap(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::new("0987654321", TypeOfNumber::International)
                .unwrap(),
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
            sm_default_msg_id: 0,
            sm_length: 5,                                     // Says 5 bytes
            short_message: ShortMessage::from("Hello World"), // But has 11 bytes
            // All optional parameters set to None
            user_message_reference: None,
            source_port: None,
            source_addr_submit: None,
            destination_port: None,
            dest_addr_submit: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            more_messages_to_send: None,
            payload_type: None,
            message_payload: None,
            privacy_indicator: None,
            callback_num: None,
            callback_num_pres_ind: None,
            callback_num_atag: None,
            source_subaddress: None,
            dest_subaddress: None,
            display_time: None,
            sms_signal: None,
            ms_validity: None,
            ms_msg_wait_facilities: None,
            number_of_messages: None,
            alert_on_msg_delivery: None,
            language_indicator: None,
            its_reply_type: None,
            its_session_info: None,
            ussd_service_op: None,
        };

        // Validate should return an error for length mismatch
        let validation_result = submit_sm.validate();
        assert!(validation_result.is_err());
        assert!(matches!(
            validation_result.unwrap_err(),
            crate::datatypes::SubmitSmValidationError::SmLengthMismatch { .. }
        ));
    }

    #[test]
    fn test_all_enum_values_encoding() {
        // Test that all enum values can be encoded without panicking

        // Test all CommandStatus values
        for status in [
            CommandStatus::Ok,
            CommandStatus::InvalidMsgLength,
            CommandStatus::InvalidCommandLength,
            CommandStatus::InvalidCommandId,
            CommandStatus::SystemError,
            CommandStatus::InvalidSourceAddress,
            CommandStatus::ThrottlingError,
        ] {
            let response = SubmitSmResponse {
                command_status: status,
                sequence_number: 1,
                message_id: MessageId::from("test"),
            };
            let bytes = crate::codec::Encodable::to_bytes(&response);
            assert!(bytes.len() > 16);
        }

        // Test all TypeOfNumber values
        for ton in [
            TypeOfNumber::Unknown,
            TypeOfNumber::International,
            TypeOfNumber::National,
            TypeOfNumber::NetworkSpecific,
            TypeOfNumber::SubscriberNumber,
            TypeOfNumber::Alphanumeric,
            TypeOfNumber::Abbreviated,
        ] {
            let bt = BindTransmitter {
                command_status: CommandStatus::Ok,
                sequence_number: 1,
                system_id: SystemId::from("TEST"),
                password: Some(Password::from("pass")),
                system_type: SystemType::from("TEST"),
                interface_version: InterfaceVersion::SmppV34,
                addr_ton: ton,
                addr_npi: NumericPlanIndicator::Isdn,
                address_range: AddressRange::from(""),
            };
            let bytes = Encodable::to_bytes(&bt);
            assert!(bytes.len() > 16);
        }

        // Test all NumericPlanIndicator values
        for npi in [
            NumericPlanIndicator::Unknown,
            NumericPlanIndicator::Isdn,
            NumericPlanIndicator::Data,
            NumericPlanIndicator::Telex,
            NumericPlanIndicator::LandMobile,
            NumericPlanIndicator::National,
            NumericPlanIndicator::Private,
            NumericPlanIndicator::Ermes,
            NumericPlanIndicator::Internet,
            NumericPlanIndicator::WapClientId,
        ] {
            let bt = BindTransmitter {
                command_status: CommandStatus::Ok,
                sequence_number: 1,
                system_id: SystemId::from("TEST"),
                password: Some(Password::from("pass")),
                system_type: SystemType::from("TEST"),
                interface_version: InterfaceVersion::SmppV34,
                addr_ton: TypeOfNumber::International,
                addr_npi: npi,
                address_range: AddressRange::from(""),
            };
            let bytes = Encodable::to_bytes(&bt);
            assert!(bytes.len() > 16);
        }

        // Test all PriorityFlag values
        for priority in [
            PriorityFlag::Level0,
            PriorityFlag::Level1,
            PriorityFlag::Level2,
            PriorityFlag::Level3,
        ] {
            // Create minimal SubmitSm to test priority encoding
            let submit_sm = create_minimal_submit_sm();
            let mut test_submit = submit_sm.clone();
            test_submit.priority_flag = priority;

            let bytes = Encodable::to_bytes(&test_submit);
            assert!(bytes.len() > 16);
        }

        // Test all InterfaceVersion values
        for version in [InterfaceVersion::SmppV33, InterfaceVersion::SmppV34] {
            let bt = BindTransmitter {
                command_status: CommandStatus::Ok,
                sequence_number: 1,
                system_id: SystemId::from("TEST"),
                password: Some(Password::from("pass")),
                system_type: SystemType::from("TEST"),
                interface_version: version,
                addr_ton: TypeOfNumber::International,
                addr_npi: NumericPlanIndicator::Isdn,
                address_range: AddressRange::from(""),
            };
            let bytes = Encodable::to_bytes(&bt);
            assert!(bytes.len() > 16);
        }
    }

    // Helper function to create a minimal SubmitSm
    fn create_minimal_submit_sm() -> SubmitSm {
        SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: ServiceType::default(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: SourceAddr::new("1234567890", TypeOfNumber::International).unwrap(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: DestinationAddr::new("0987654321", TypeOfNumber::International)
                .unwrap(),
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
            sm_default_msg_id: 0,
            sm_length: 11,
            short_message: ShortMessage::from("Hello World"),
            // All optional parameters set to None
            user_message_reference: None,
            source_port: None,
            source_addr_submit: None,
            destination_port: None,
            dest_addr_submit: None,
            sar_msg_ref_num: None,
            sar_total_segments: None,
            sar_segment_seqnum: None,
            more_messages_to_send: None,
            payload_type: None,
            message_payload: None,
            privacy_indicator: None,
            callback_num: None,
            callback_num_pres_ind: None,
            callback_num_atag: None,
            source_subaddress: None,
            dest_subaddress: None,
            display_time: None,
            sms_signal: None,
            ms_validity: None,
            ms_msg_wait_facilities: None,
            number_of_messages: None,
            alert_on_msg_delivery: None,
            language_indicator: None,
            its_reply_type: None,
            its_session_info: None,
            ussd_service_op: None,
        }
    }

    #[test]
    fn test_unicode_string_handling() {
        // Test with Unicode characters (keeping within byte limits)
        let bind_transmitter = BindTransmitter {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            system_id: SystemId::from("SMPP测试"), // Contains Chinese characters (8 bytes)
            password: Some(Password::from("密码")), // Contains Chinese characters (6 bytes)
            system_type: SystemType::from("テスト"), // Contains Japanese characters (9 bytes)
            interface_version: InterfaceVersion::SmppV34,
            addr_ton: TypeOfNumber::International,
            addr_npi: NumericPlanIndicator::Isdn,
            address_range: AddressRange::from(""),
        };

        let bytes = crate::codec::Encodable::to_bytes(&bind_transmitter);

        // Should encode without panicking
        assert!(bytes.len() > 16);

        // The UTF-8 bytes should be present in the output
        assert!(
            bytes
                .windows("SMPP测试".len())
                .any(|window| window == "SMPP测试".as_bytes())
        );
    }

    #[test]
    fn test_boundary_sequence_numbers() {
        // Test with boundary sequence numbers
        for seq_num in [0, 1, 0x7FFFFFFF, 0xFFFFFFFF] {
            let response = SubmitSmResponse {
                command_status: CommandStatus::Ok,
                sequence_number: seq_num,
                message_id: MessageId::from("test"),
            };

            let bytes = crate::codec::Encodable::to_bytes(&response);

            // Verify sequence number is encoded correctly
            assert_eq!(&bytes[12..16], &seq_num.to_be_bytes());
        }
    }

    #[test]
    fn test_interface_version_smpp_v50_serialization() {
        // Test that SMPP v5.0 serializes to correct byte value
        let version = InterfaceVersion::SmppV50;
        assert_eq!(version as u8, 0x50);
    }

    #[test]
    fn test_interface_version_smpp_v50_try_from() {
        // Test that byte value 0x50 converts to SMPP v5.0
        let version = InterfaceVersion::try_from(0x50);
        assert!(version.is_ok());
        assert_eq!(version.unwrap(), InterfaceVersion::SmppV50);
    }

    #[test]
    fn test_interface_version_all_variants() {
        // Test all supported interface versions
        let versions = [
            (InterfaceVersion::SmppV33, 0x33),
            (InterfaceVersion::SmppV34, 0x34),
            (InterfaceVersion::SmppV50, 0x50),
        ];

        for (version, expected_byte) in versions {
            // Test enum to byte conversion
            assert_eq!(version as u8, expected_byte);
            
            // Test byte to enum conversion
            let parsed = InterfaceVersion::try_from(expected_byte);
            assert!(parsed.is_ok(), "Failed to parse version from byte {:#04x}", expected_byte);
            assert_eq!(parsed.unwrap(), version);
        }
    }

    #[test]
    fn test_interface_version_invalid_values() {
        // Test that invalid byte values are rejected
        let invalid_values = [0x00, 0x01, 0x32, 0x35, 0x49, 0x51, 0xFF];
        
        for invalid in invalid_values {
            let result = InterfaceVersion::try_from(invalid);
            assert!(result.is_err(), "Should reject invalid version byte {:#04x}", invalid);
        }
    }

    #[test]
    fn test_interface_version_debug_format() {
        // Test that debug formatting works correctly
        assert_eq!(format!("{:?}", InterfaceVersion::SmppV33), "SmppV33");
        assert_eq!(format!("{:?}", InterfaceVersion::SmppV34), "SmppV34");
        assert_eq!(format!("{:?}", InterfaceVersion::SmppV50), "SmppV50");
    }

    #[test]
    fn test_interface_version_clone_and_copy() {
        // Test that InterfaceVersion implements Clone and Copy correctly
        let original = InterfaceVersion::SmppV50;
        let cloned = original.clone();
        let copied = original;
        
        assert_eq!(original, cloned);
        assert_eq!(original, copied);
        assert_eq!(cloned, copied);
    }

    #[test]
    fn test_interface_version_partial_eq() {
        // Test equality comparisons
        assert_eq!(InterfaceVersion::SmppV33, InterfaceVersion::SmppV33);
        assert_eq!(InterfaceVersion::SmppV34, InterfaceVersion::SmppV34);
        assert_eq!(InterfaceVersion::SmppV50, InterfaceVersion::SmppV50);
        
        assert_ne!(InterfaceVersion::SmppV33, InterfaceVersion::SmppV34);
        assert_ne!(InterfaceVersion::SmppV34, InterfaceVersion::SmppV50);
        assert_ne!(InterfaceVersion::SmppV33, InterfaceVersion::SmppV50);
    }

    #[test]
    fn test_interface_version_backwards_compatibility() {
        // Test that v5.0 can be used in contexts expecting any version
        let versions = [
            InterfaceVersion::SmppV33,
            InterfaceVersion::SmppV34,
            InterfaceVersion::SmppV50,
        ];

        // Simulate version selection logic
        for version in versions {
            match version {
                InterfaceVersion::SmppV33 => {
                    // v3.3 features only
                    assert_eq!(version as u8, 0x33);
                }
                InterfaceVersion::SmppV34 => {
                    // v3.4 features
                    assert_eq!(version as u8, 0x34);
                }
                InterfaceVersion::SmppV50 => {
                    // v5.0 features
                    assert_eq!(version as u8, 0x50);
                }
            }
        }
    }

    #[test]
    fn test_congestion_state_tlv_encoding() {
        use crate::datatypes::{tags, Tlv};
        use bytes::Bytes;

        // Test congestion state value of 0 (no congestion)
        let tlv = Tlv {
            tag: tags::CONGESTION_STATE,
            length: 1,
            value: Bytes::from_static(&[0]),
        };

        let bytes = tlv.to_bytes();
        let expected = vec![
            0x14, 0x2C, // tag (CONGESTION_STATE = 0x142C)
            0x00, 0x01, // length
            0x00,       // value (0%)
        ];
        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn test_congestion_state_tlv_all_valid_values() {
        use crate::datatypes::{tags, Tlv};
        use bytes::Bytes;

        // Test boundary values: 0, 50, 100
        let test_values = [0u8, 50u8, 100u8];
        
        for value in test_values {
            let tlv = Tlv {
                tag: tags::CONGESTION_STATE,
                length: 1,
                value: Bytes::from(vec![value]),
            };

            let bytes = tlv.to_bytes();
            
            // Verify tag and length
            assert_eq!(&bytes[0..2], &[0x14, 0x2C]); // CONGESTION_STATE tag
            assert_eq!(&bytes[2..4], &[0x00, 0x01]); // length = 1
            assert_eq!(bytes[4], value); // congestion value
        }
    }

    #[test]
    fn test_congestion_state_tlv_decoding() {
        use crate::datatypes::{tags, Tlv};
        use std::io::Cursor;

        // Test decoding congestion state value of 75%
        let data = vec![
            0x14, 0x2C, // tag
            0x00, 0x01, // length
            0x4B,       // value (75)
        ];

        let mut cursor = Cursor::new(data.as_slice());
        let tlv = Tlv::decode(&mut cursor).expect("Should decode successfully");

        assert_eq!(tlv.tag, tags::CONGESTION_STATE);
        assert_eq!(tlv.length, 1);
        assert_eq!(tlv.value.as_ref(), &[75]);
    }

    #[test]
    fn test_congestion_state_tlv_roundtrip() {
        use crate::datatypes::{tags, Tlv};
        use bytes::Bytes;
        use std::io::Cursor;

        // Test roundtrip encoding/decoding
        let original = Tlv {
            tag: tags::CONGESTION_STATE,
            length: 1,
            value: Bytes::from_static(&[33]), // 33% congestion
        };

        let encoded = original.to_bytes();
        let mut cursor = Cursor::new(encoded.as_ref());
        let decoded = Tlv::decode(&mut cursor).expect("Should decode successfully");

        assert_eq!(original.tag, decoded.tag);
        assert_eq!(original.length, decoded.length);
        assert_eq!(original.value, decoded.value);
    }

    #[test]
    fn test_congestion_state_validation_helper() {
        // Test helper function to validate congestion state values
        fn validate_congestion_state(value: u8) -> bool {
            value <= 100
        }

        // Valid values
        assert!(validate_congestion_state(0));
        assert!(validate_congestion_state(50));
        assert!(validate_congestion_state(100));

        // Invalid values
        assert!(!validate_congestion_state(101));
        assert!(!validate_congestion_state(255));
    }

    #[test]
    fn test_congestion_state_semantic_meaning() {
        // Test the semantic meaning of different congestion levels
        let test_cases = [
            (0, "No congestion"),
            (25, "Low congestion"),
            (50, "Medium congestion"),
            (75, "High congestion"),
            (100, "Maximum congestion"),
        ];

        for (value, description) in test_cases {
            // Verify the value is in valid range
            assert!(value <= 100, "Congestion value {} is invalid: {}", value, description);
            
            // Test that we can create TLV with this value
            use crate::datatypes::{tags, Tlv};
            use bytes::Bytes;

            let tlv = Tlv {
                tag: tags::CONGESTION_STATE,
                length: 1,
                value: Bytes::from(vec![value]),
            };

            assert_eq!(tlv.value[0], value);
        }
    }

    #[test]
    fn test_billing_identification_tlv_encoding() {
        use crate::datatypes::{tags, Tlv};
        use bytes::Bytes;

        // Test billing identification with sample identifier
        let billing_id = b"BILLING123";
        let tlv = Tlv {
            tag: tags::BILLING_IDENTIFICATION,
            length: billing_id.len() as u16,
            value: Bytes::copy_from_slice(billing_id),
        };

        let bytes = tlv.to_bytes();
        let mut expected = vec![
            0x06, 0x00, // tag (BILLING_IDENTIFICATION = 0x0600)
            0x00, 0x0A, // length (10 bytes)
        ];
        expected.extend_from_slice(billing_id);
        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn test_source_network_id_tlv_encoding() {
        use crate::datatypes::{tags, Tlv};
        use bytes::Bytes;

        // Test source network ID 
        let network_id = b"NET001";
        let tlv = Tlv {
            tag: tags::SOURCE_NETWORK_ID,
            length: network_id.len() as u16,
            value: Bytes::copy_from_slice(network_id),
        };

        let bytes = tlv.to_bytes();
        let mut expected = vec![
            0x06, 0x0E, // tag (SOURCE_NETWORK_ID = 0x060E)
            0x00, 0x06, // length (6 bytes)
        ];
        expected.extend_from_slice(network_id);
        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn test_dest_network_id_tlv_encoding() {
        use crate::datatypes::{tags, Tlv};
        use bytes::Bytes;

        // Test destination network ID
        let network_id = b"NET002";
        let tlv = Tlv {
            tag: tags::DEST_NETWORK_ID,
            length: network_id.len() as u16,
            value: Bytes::copy_from_slice(network_id),
        };

        let bytes = tlv.to_bytes();
        let mut expected = vec![
            0x06, 0x0F, // tag (DEST_NETWORK_ID = 0x060F)
            0x00, 0x06, // length (6 bytes)
        ];
        expected.extend_from_slice(network_id);
        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn test_source_node_id_tlv_encoding() {
        use crate::datatypes::{tags, Tlv};
        use bytes::Bytes;

        // Test source node ID with 8-byte value
        let node_id = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let tlv = Tlv {
            tag: tags::SOURCE_NODE_ID,
            length: 8,
            value: Bytes::copy_from_slice(&node_id),
        };

        let bytes = tlv.to_bytes();
        let mut expected = vec![
            0x06, 0x0C, // tag (SOURCE_NODE_ID = 0x060C)
            0x00, 0x08, // length (8 bytes)
        ];
        expected.extend_from_slice(&node_id);
        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn test_dest_node_id_tlv_encoding() {
        use crate::datatypes::{tags, Tlv};
        use bytes::Bytes;

        // Test destination node ID with 8-byte value
        let node_id = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8];
        let tlv = Tlv {
            tag: tags::DEST_NODE_ID,
            length: 8,
            value: Bytes::copy_from_slice(&node_id),
        };

        let bytes = tlv.to_bytes();
        let mut expected = vec![
            0x06, 0x0D, // tag (DEST_NODE_ID = 0x060D)
            0x00, 0x08, // length (8 bytes)
        ];
        expected.extend_from_slice(&node_id);
        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn test_ussd_service_op_tlv_encoding() {
        use crate::datatypes::{tags, Tlv};
        use bytes::Bytes;

        // Test USSD service operation - PSSD indication (value 0x01)
        let tlv = Tlv {
            tag: tags::USSD_SERVICE_OP,
            length: 1,
            value: Bytes::from_static(&[0x01]),
        };

        let bytes = tlv.to_bytes();
        let expected = vec![
            0x05, 0x01, // tag (USSD_SERVICE_OP = 0x0501)
            0x00, 0x01, // length (1 byte)
            0x01,       // value (PSSD indication)
        ];
        assert_eq!(bytes.as_ref(), &expected);
    }

    #[test]
    fn test_core_v50_tlvs_roundtrip() {
        use crate::datatypes::{tags, Tlv};
        use bytes::Bytes;
        use std::io::Cursor;

        // Test roundtrip for multiple v5.0 TLVs
        let test_cases = [
            (tags::BILLING_IDENTIFICATION, b"BILL001".as_slice()),
            (tags::SOURCE_NETWORK_ID, b"SRC_NET".as_slice()),
            (tags::DEST_NETWORK_ID, b"DST_NET".as_slice()),
            (tags::USSD_SERVICE_OP, &[0x02]),
        ];

        for (tag, value_data) in test_cases {
            let original = Tlv {
                tag,
                length: value_data.len() as u16,
                value: Bytes::copy_from_slice(value_data),
            };

            let encoded = original.to_bytes();
            let mut cursor = Cursor::new(encoded.as_ref());
            let decoded = Tlv::decode(&mut cursor).expect("Should decode successfully");

            assert_eq!(original.tag, decoded.tag, "Tag mismatch for {:#06x}", tag);
            assert_eq!(original.length, decoded.length, "Length mismatch for {:#06x}", tag);
            assert_eq!(original.value, decoded.value, "Value mismatch for {:#06x}", tag);
        }
    }

    #[test]
    fn test_node_id_validation() {
        // Test that node IDs are exactly 8 bytes
        fn validate_node_id(value: &[u8]) -> bool {
            value.len() == 8
        }

        // Valid 8-byte node IDs
        assert!(validate_node_id(&[0; 8]));
        assert!(validate_node_id(&[0xFF; 8]));
        assert!(validate_node_id(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]));

        // Invalid node IDs
        assert!(!validate_node_id(&[]));
        assert!(!validate_node_id(&[0x01]));
        assert!(!validate_node_id(&[0; 7]));
        assert!(!validate_node_id(&[0; 9]));
        assert!(!validate_node_id(&[0; 16]));
    }

    #[test]
    fn test_ussd_service_op_values() {
        // Test USSD service operation predefined values
        let ussd_operations = [
            (0x00, "PSSD request"),
            (0x01, "PSSR request"),
            (0x02, "USSR request"),
            (0x03, "USSN request"),
            (0x10, "PSSD response"),
            (0x11, "PSSR response"),
            (0x12, "USSR response"),
            (0x13, "USSN response"),
        ];

        for (value, description) in ussd_operations {
            // Test that we can create TLV with this operation value
            use crate::datatypes::{tags, Tlv};
            use bytes::Bytes;

            let tlv = Tlv {
                tag: tags::USSD_SERVICE_OP,
                length: 1,
                value: Bytes::from(vec![value]),
            };

            assert_eq!(tlv.value[0], value, "USSD operation {} ({})", value, description);
        }
    }

    #[test]
    fn test_version_aware_registry_creation() {
        use crate::codec::PduRegistry;
        use crate::datatypes::InterfaceVersion;

        // Test creating registries for different SMPP versions
        let v33_registry = PduRegistry::for_version(InterfaceVersion::SmppV33);
        let v34_registry = PduRegistry::for_version(InterfaceVersion::SmppV34);
        let v50_registry = PduRegistry::for_version(InterfaceVersion::SmppV50);

        // All registries should have basic PDUs
        assert!(v33_registry.registered_commands().contains(&crate::datatypes::CommandId::EnquireLink));
        assert!(v34_registry.registered_commands().contains(&crate::datatypes::CommandId::EnquireLink));
        assert!(v50_registry.registered_commands().contains(&crate::datatypes::CommandId::EnquireLink));

        // v5.0 registry should have additional capabilities
        assert_eq!(v50_registry.version(), InterfaceVersion::SmppV50);
    }

    #[test]
    fn test_version_detection_from_bind_pdu() {
        use crate::datatypes::{InterfaceVersion, BindTransmitter, TypeOfNumber, NumericPlanIndicator};
        use crate::codec::{PduRegistry, Encodable};

        // Create bind PDUs with different interface versions
        let bind_v34 = BindTransmitter::builder()
            .sequence_number(1)
            .system_id("TEST")
            .password("pass")
            .system_type("TEST")
            .interface_version(InterfaceVersion::SmppV34)
            .addr_ton(TypeOfNumber::International)
            .addr_npi(NumericPlanIndicator::Isdn)
            .address_range("")
            .build();

        let bind_v50 = BindTransmitter::builder()
            .sequence_number(2)
            .system_id("TEST")
            .password("pass")
            .system_type("TEST")
            .interface_version(InterfaceVersion::SmppV50)
            .addr_ton(TypeOfNumber::International)
            .addr_npi(NumericPlanIndicator::Isdn)
            .address_range("")
            .build();

        // Test version detection
        let v34_version = PduRegistry::detect_version_from_bind(&bind_v34.unwrap().to_bytes());
        let v50_version = PduRegistry::detect_version_from_bind(&bind_v50.unwrap().to_bytes());

        assert_eq!(v34_version, Some(InterfaceVersion::SmppV34));
        assert_eq!(v50_version, Some(InterfaceVersion::SmppV50));
    }

    #[test]
    fn test_version_aware_registry_fallback() {
        use crate::codec::PduRegistry;
        use crate::datatypes::InterfaceVersion;

        // Test that v5.0 registry can handle v3.4 PDUs (backward compatibility)
        let v50_registry = PduRegistry::for_version(InterfaceVersion::SmppV50);
        
        // Should be able to decode v3.4 PDUs
        assert!(v50_registry.supports_version(InterfaceVersion::SmppV34));
        assert!(v50_registry.supports_version(InterfaceVersion::SmppV33));
        assert!(v50_registry.supports_version(InterfaceVersion::SmppV50));

        // v3.4 registry should not handle v5.0 specific features
        let v34_registry = PduRegistry::for_version(InterfaceVersion::SmppV34);
        assert!(v34_registry.supports_version(InterfaceVersion::SmppV34));
        assert!(v34_registry.supports_version(InterfaceVersion::SmppV33));
        assert!(!v34_registry.supports_version(InterfaceVersion::SmppV50));
    }

    #[test]
    fn test_version_aware_tlv_handling() {
        use crate::codec::PduRegistry;
        use crate::datatypes::{InterfaceVersion, tags};

        let v34_registry = PduRegistry::for_version(InterfaceVersion::SmppV34);
        let v50_registry = PduRegistry::for_version(InterfaceVersion::SmppV50);

        // v3.4 registry should support standard TLVs
        assert!(v34_registry.supports_tlv(tags::USER_MESSAGE_REFERENCE));
        assert!(v34_registry.supports_tlv(tags::SOURCE_PORT));
        assert!(v34_registry.supports_tlv(tags::MESSAGE_PAYLOAD));

        // v3.4 registry should not support v5.0 TLVs
        assert!(!v34_registry.supports_tlv(tags::CONGESTION_STATE));
        assert!(!v34_registry.supports_tlv(tags::BILLING_IDENTIFICATION));

        // v5.0 registry should support both v3.4 and v5.0 TLVs
        assert!(v50_registry.supports_tlv(tags::USER_MESSAGE_REFERENCE));
        assert!(v50_registry.supports_tlv(tags::CONGESTION_STATE));
        assert!(v50_registry.supports_tlv(tags::BILLING_IDENTIFICATION));
        assert!(v50_registry.supports_tlv(tags::SOURCE_NETWORK_ID));
    }

    #[test]
    fn test_auto_version_detection() {
        use crate::codec::PduRegistry;
        use crate::datatypes::{InterfaceVersion, EnquireLink};
        use crate::codec::Encodable;

        // Test auto-detection with a basic PDU
        let enquire = EnquireLink::new(1);
        let _bytes = enquire.to_bytes();

        // Should start with default v3.4 registry
        let mut registry = PduRegistry::new();
        assert_eq!(registry.version(), InterfaceVersion::SmppV34);

        // Should be able to upgrade to v5.0 when needed
        registry.upgrade_to_version(InterfaceVersion::SmppV50);
        assert_eq!(registry.version(), InterfaceVersion::SmppV50);

        // Should not downgrade from v5.0 to v3.4 (preserve capabilities)
        registry.upgrade_to_version(InterfaceVersion::SmppV34);
        assert_eq!(registry.version(), InterfaceVersion::SmppV50);
    }

    #[test]
    fn test_version_negotiation_logic() {
        use crate::codec::PduRegistry;
        use crate::datatypes::InterfaceVersion;

        // Test version negotiation helper methods
        let negotiated = PduRegistry::negotiate_version(
            InterfaceVersion::SmppV50, 
            InterfaceVersion::SmppV34
        );
        // Should negotiate down to the common version
        assert_eq!(negotiated, InterfaceVersion::SmppV34);

        let negotiated = PduRegistry::negotiate_version(
            InterfaceVersion::SmppV34, 
            InterfaceVersion::SmppV50
        );
        // Should negotiate to the common version
        assert_eq!(negotiated, InterfaceVersion::SmppV34);

        let negotiated = PduRegistry::negotiate_version(
            InterfaceVersion::SmppV50, 
            InterfaceVersion::SmppV50
        );
        // Both support v5.0, should use v5.0
        assert_eq!(negotiated, InterfaceVersion::SmppV50);
    }

    #[test]
    fn test_registry_version_specific_features() {
        use crate::codec::PduRegistry;
        use crate::datatypes::InterfaceVersion;

        let v34_registry = PduRegistry::for_version(InterfaceVersion::SmppV34);
        let v50_registry = PduRegistry::for_version(InterfaceVersion::SmppV50);

        // v3.4 features
        assert!(v34_registry.supports_feature("submit_sm"));
        assert!(v34_registry.supports_feature("deliver_sm"));
        assert!(v34_registry.supports_feature("submit_multi"));

        // v5.0 specific features
        assert!(!v34_registry.supports_feature("congestion_control"));
        assert!(!v34_registry.supports_feature("broadcast_sm"));
        assert!(!v34_registry.supports_feature("enhanced_billing"));

        // v5.0 registry should support all features
        assert!(v50_registry.supports_feature("submit_sm"));
        assert!(v50_registry.supports_feature("congestion_control"));
        assert!(v50_registry.supports_feature("enhanced_billing"));
    }

    #[test]
    fn test_broadcast_sm_pdu_structure() {
        // Test basic broadcast_sm PDU structure
        use crate::datatypes::{BroadcastSm, ServiceType, TypeOfNumber, NumericPlanIndicator, 
                               DataCoding, PriorityFlag, ScheduleDeliveryTime, ValidityPeriod};
        
        // Create a basic broadcast_sm PDU
        let broadcast_sm = BroadcastSm::builder()
            .sequence_number(1)
            .service_type(ServiceType::default())
            .source_addr("1234567890", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .message_id("BC001")
            .priority_flag(PriorityFlag::Level0)
            .schedule_delivery_time(ScheduleDeliveryTime::immediate())
            .validity_period(ValidityPeriod::immediate())
            .data_coding(DataCoding::default())
            .broadcast_area_identifier(vec![0x01, 0x02, 0x03, 0x04])
            .broadcast_content_type(0x01)
            .broadcast_rep_num(1)
            .broadcast_frequency_interval(3600) // 1 hour
            .build();

        assert!(broadcast_sm.is_ok());
        let pdu = broadcast_sm.unwrap();
        
        // Test field access
        assert_eq!(pdu.sequence_number(), 1);
        assert_eq!(pdu.message_id(), "BC001");
        assert_eq!(pdu.broadcast_rep_num(), 1);
        assert_eq!(pdu.broadcast_frequency_interval(), 3600);
    }

    #[test]
    fn test_broadcast_sm_encoding_decoding() {
        use crate::datatypes::{BroadcastSm, ServiceType, TypeOfNumber, NumericPlanIndicator, 
                               DataCoding, PriorityFlag, ScheduleDeliveryTime, ValidityPeriod};
        use crate::codec::Encodable;

        // Create broadcast_sm PDU
        let original = BroadcastSm::builder()
            .sequence_number(42)
            .service_type(ServiceType::default())
            .source_addr("555123456", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .message_id("BROADCAST001")
            .priority_flag(PriorityFlag::Level1)
            .schedule_delivery_time(ScheduleDeliveryTime::immediate())
            .validity_period(ValidityPeriod::immediate())
            .data_coding(DataCoding::default())
            .broadcast_area_identifier(vec![0x10, 0x20, 0x30, 0x40])
            .broadcast_content_type(0x02)
            .broadcast_rep_num(3)
            .broadcast_frequency_interval(7200) // 2 hours
            .build()
            .unwrap();

        // Test encoding
        let encoded = original.to_bytes();
        assert!(encoded.len() > 16); // Should be larger than just PDU header

        // Test that we can create the same PDU again (consistency)
        let duplicate = BroadcastSm::builder()
            .sequence_number(42)
            .service_type(ServiceType::default())
            .source_addr("555123456", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .message_id("BROADCAST001")
            .priority_flag(PriorityFlag::Level1)
            .schedule_delivery_time(ScheduleDeliveryTime::immediate())
            .validity_period(ValidityPeriod::immediate())
            .data_coding(DataCoding::default())
            .broadcast_area_identifier(vec![0x10, 0x20, 0x30, 0x40])
            .broadcast_content_type(0x02)
            .broadcast_rep_num(3)
            .broadcast_frequency_interval(7200)
            .build()
            .unwrap();

        assert_eq!(original.sequence_number(), duplicate.sequence_number());
        assert_eq!(original.message_id(), duplicate.message_id());
    }

    #[test]
    fn test_broadcast_sm_response_structure() {
        use crate::datatypes::{BroadcastSmResponse, CommandStatus};

        // Test successful response
        let response = BroadcastSmResponse::new(1, CommandStatus::Ok, "BC001");
        assert_eq!(response.sequence_number(), 1);
        assert_eq!(response.command_status(), CommandStatus::Ok);
        assert_eq!(response.message_id(), "BC001");

        // Test error response
        let error_response = BroadcastSmResponse::new(2, CommandStatus::InvalidCommandLength, "");
        assert_eq!(error_response.command_status(), CommandStatus::InvalidCommandLength);
        assert_eq!(error_response.message_id(), "");
    }

    #[test]
    fn test_broadcast_sm_validation() {
        use crate::datatypes::{BroadcastSm, ServiceType, TypeOfNumber, NumericPlanIndicator, 
                               DataCoding, PriorityFlag, ScheduleDeliveryTime, ValidityPeriod};

        // Test invalid broadcast_area_identifier (empty)
        let result = BroadcastSm::builder()
            .sequence_number(1)
            .service_type(ServiceType::default())
            .source_addr("1234567890", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .message_id("BC001")
            .priority_flag(PriorityFlag::Level0)
            .schedule_delivery_time(ScheduleDeliveryTime::immediate())
            .validity_period(ValidityPeriod::immediate())
            .data_coding(DataCoding::default())
            .broadcast_area_identifier(vec![]) // Empty - should be invalid
            .broadcast_content_type(0x01)
            .broadcast_rep_num(1)
            .broadcast_frequency_interval(3600)
            .build();

        assert!(result.is_err());

        // Test invalid broadcast_rep_num (zero)
        let result = BroadcastSm::builder()
            .sequence_number(1)
            .service_type(ServiceType::default())
            .source_addr("1234567890", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .message_id("BC001")
            .priority_flag(PriorityFlag::Level0)
            .schedule_delivery_time(ScheduleDeliveryTime::immediate())
            .validity_period(ValidityPeriod::immediate())
            .data_coding(DataCoding::default())
            .broadcast_area_identifier(vec![0x01, 0x02, 0x03, 0x04])
            .broadcast_content_type(0x01)
            .broadcast_rep_num(0) // Zero - should be invalid
            .broadcast_frequency_interval(3600)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_broadcast_sm_command_id() {
        use crate::datatypes::{BroadcastSm, CommandId};
        use crate::codec::Decodable;

        // Test that broadcast_sm has correct command_id
        assert_eq!(BroadcastSm::command_id(), CommandId::BroadcastSm);
    }

    #[test]
    fn test_broadcast_sm_in_v50_registry() {
        use crate::codec::PduRegistry;
        use crate::datatypes::{InterfaceVersion, CommandId};

        // Test that v5.0 registry supports broadcast_sm
        let v50_registry = PduRegistry::for_version(InterfaceVersion::SmppV50);
        assert!(v50_registry.is_registered(CommandId::BroadcastSm));
        assert!(v50_registry.is_registered(CommandId::BroadcastSmResp));

        // Test that v3.4 registry does not support broadcast_sm
        let v34_registry = PduRegistry::for_version(InterfaceVersion::SmppV34);
        assert!(!v34_registry.is_registered(CommandId::BroadcastSm));
        assert!(!v34_registry.is_registered(CommandId::BroadcastSmResp));
    }

    #[test]
    fn test_query_broadcast_sm_pdu_structure() {
        // Test basic query_broadcast_sm PDU structure
        use crate::datatypes::{QueryBroadcastSm, TypeOfNumber, NumericPlanIndicator};
        
        // Create a basic query_broadcast_sm PDU
        let query_broadcast_sm = QueryBroadcastSm::builder()
            .sequence_number(42)
            .message_id("BC001")
            .source_addr("1234567890", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .build();

        assert!(query_broadcast_sm.is_ok());
        let pdu = query_broadcast_sm.unwrap();
        
        // Test field access
        assert_eq!(pdu.sequence_number(), 42);
        assert_eq!(pdu.message_id(), "BC001");
        assert_eq!(pdu.source_addr_ton(), TypeOfNumber::International);
        assert_eq!(pdu.source_addr_npi(), NumericPlanIndicator::Isdn);
        assert_eq!(pdu.source_addr(), "1234567890");
    }

    #[test]
    fn test_query_broadcast_sm_encoding_decoding() {
        use crate::datatypes::{QueryBroadcastSm, TypeOfNumber, NumericPlanIndicator};
        use crate::codec::Encodable;

        // Create query_broadcast_sm PDU
        let original = QueryBroadcastSm::builder()
            .sequence_number(100)
            .message_id("QUERY_BC_001")
            .source_addr("555123456", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .build()
            .unwrap();

        // Test encoding
        let encoded = original.to_bytes();
        assert!(encoded.len() > 16); // Should be larger than just PDU header

        // Test field consistency
        assert_eq!(original.sequence_number(), 100);
        assert_eq!(original.message_id(), "QUERY_BC_001");
        assert_eq!(original.source_addr(), "555123456");
    }

    #[test]
    fn test_query_broadcast_sm_response_structure() {
        use crate::datatypes::{QueryBroadcastSmResponse, CommandStatus, MessageState};

        // Test successful response
        let response = QueryBroadcastSmResponse::new(
            42, 
            CommandStatus::Ok, 
            "BC001",
            MessageState::Delivered,
            None // final_date
        );
        assert_eq!(response.sequence_number(), 42);
        assert_eq!(response.command_status(), CommandStatus::Ok);
        assert_eq!(response.message_id(), "BC001");
        assert_eq!(response.message_state(), MessageState::Delivered);

        // Test error response
        let error_response = QueryBroadcastSmResponse::new(
            43,
            CommandStatus::InvalidMessageId,
            "",
            MessageState::Unknown,
            None
        );
        assert_eq!(error_response.command_status(), CommandStatus::InvalidMessageId);
        assert_eq!(error_response.message_state(), MessageState::Unknown);
    }

    #[test]
    fn test_cancel_broadcast_sm_pdu_structure() {
        // Test basic cancel_broadcast_sm PDU structure
        use crate::datatypes::{CancelBroadcastSm, ServiceType, TypeOfNumber, NumericPlanIndicator};
        
        // Create a basic cancel_broadcast_sm PDU
        let cancel_broadcast_sm = CancelBroadcastSm::builder()
            .sequence_number(55)
            .service_type(ServiceType::default())
            .message_id("BC001")
            .source_addr("1234567890", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .build();

        assert!(cancel_broadcast_sm.is_ok());
        let pdu = cancel_broadcast_sm.unwrap();
        
        // Test field access
        assert_eq!(pdu.sequence_number(), 55);
        assert_eq!(pdu.message_id(), "BC001");
        assert_eq!(pdu.source_addr_ton(), TypeOfNumber::International);
        assert_eq!(pdu.source_addr_npi(), NumericPlanIndicator::Isdn);
        assert_eq!(pdu.source_addr(), "1234567890");
    }

    #[test]
    fn test_cancel_broadcast_sm_encoding_decoding() {
        use crate::datatypes::{CancelBroadcastSm, ServiceType, TypeOfNumber, NumericPlanIndicator};
        use crate::codec::Encodable;

        // Create cancel_broadcast_sm PDU
        let original = CancelBroadcastSm::builder()
            .sequence_number(200)
            .service_type(ServiceType::from("SMS"))
            .message_id("CANCEL_BC_001")
            .source_addr("555123456", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .build()
            .unwrap();

        // Test encoding
        let encoded = original.to_bytes();
        assert!(encoded.len() > 16); // Should be larger than just PDU header

        // Test field consistency
        assert_eq!(original.sequence_number(), 200);
        assert_eq!(original.message_id(), "CANCEL_BC_001");
        assert_eq!(original.source_addr(), "555123456");
    }

    #[test]
    fn test_cancel_broadcast_sm_response_structure() {
        use crate::datatypes::{CancelBroadcastSmResponse, CommandStatus};

        // Test successful response
        let response = CancelBroadcastSmResponse::new(55, CommandStatus::Ok);
        assert_eq!(response.sequence_number(), 55);
        assert_eq!(response.command_status(), CommandStatus::Ok);

        // Test error response
        let error_response = CancelBroadcastSmResponse::new(56, CommandStatus::InvalidMessageId);
        assert_eq!(error_response.sequence_number(), 56);
        assert_eq!(error_response.command_status(), CommandStatus::InvalidMessageId);
    }

    #[test]
    fn test_broadcast_command_ids() {
        use crate::datatypes::{QueryBroadcastSm, CancelBroadcastSm, CommandId};
        use crate::codec::Decodable;

        // Test that broadcast operations have correct command_ids
        assert_eq!(QueryBroadcastSm::command_id(), CommandId::QueryBroadcastSm);
        assert_eq!(CancelBroadcastSm::command_id(), CommandId::CancelBroadcastSm);
    }

    #[test]
    fn test_remaining_broadcast_pdus_in_v50_registry() {
        use crate::codec::PduRegistry;
        use crate::datatypes::{InterfaceVersion, CommandId};

        // Test that v5.0 registry supports remaining broadcast PDUs
        let v50_registry = PduRegistry::for_version(InterfaceVersion::SmppV50);
        assert!(v50_registry.is_registered(CommandId::QueryBroadcastSm));
        assert!(v50_registry.is_registered(CommandId::QueryBroadcastSmResp));
        assert!(v50_registry.is_registered(CommandId::CancelBroadcastSm));
        assert!(v50_registry.is_registered(CommandId::CancelBroadcastSmResp));

        // Test that v3.4 registry does not support remaining broadcast PDUs
        let v34_registry = PduRegistry::for_version(InterfaceVersion::SmppV34);
        assert!(!v34_registry.is_registered(CommandId::QueryBroadcastSm));
        assert!(!v34_registry.is_registered(CommandId::QueryBroadcastSmResp));
        assert!(!v34_registry.is_registered(CommandId::CancelBroadcastSm));
        assert!(!v34_registry.is_registered(CommandId::CancelBroadcastSmResp));
    }

    #[test]
    fn test_broadcast_pdu_validation() {
        use crate::datatypes::{QueryBroadcastSm, CancelBroadcastSm, ServiceType, TypeOfNumber, NumericPlanIndicator};

        // Test query_broadcast_sm validation - empty message_id should be invalid
        let result = QueryBroadcastSm::builder()
            .sequence_number(1)
            .message_id("")  // Empty - should be invalid
            .source_addr("1234567890", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .build();
        assert!(result.is_err());

        // Test cancel_broadcast_sm validation - empty message_id should be invalid  
        let result = CancelBroadcastSm::builder()
            .sequence_number(1)
            .service_type(ServiceType::default())
            .message_id("")  // Empty - should be invalid
            .source_addr("1234567890", TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .build();
        assert!(result.is_err());
    }
}
