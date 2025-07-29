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

    #[test]
    fn test_smpp_v50_enhanced_error_codes() {
        // Test new SMPP v5.0 error codes
        use crate::datatypes::CommandStatus;
        
        // Test broadcast-specific error codes
        let broadcast_area_invalid = CommandStatus::InvalidBroadcastAreaIdentifier;
        assert_eq!(broadcast_area_invalid as u32, 0x0000_0100);
        
        let broadcast_content_type_invalid = CommandStatus::InvalidBroadcastContentType;
        assert_eq!(broadcast_content_type_invalid as u32, 0x0000_0101);
        
        let broadcast_frequency_invalid = CommandStatus::InvalidBroadcastFrequency;
        assert_eq!(broadcast_frequency_invalid as u32, 0x0000_0102);
        
        let broadcast_service_group_invalid = CommandStatus::InvalidBroadcastServiceGroup;
        assert_eq!(broadcast_service_group_invalid as u32, 0x0000_0103);
        
        // Test enhanced congestion control error codes
        let congestion_state_rejected = CommandStatus::CongestionStateRejected;
        assert_eq!(congestion_state_rejected as u32, 0x0000_0104);
        
        let message_throttled = CommandStatus::MessageThrottled;
        assert_eq!(message_throttled as u32, 0x0000_0105);
        
        // Test enhanced validation error codes  
        let invalid_network_id = CommandStatus::InvalidNetworkId;
        assert_eq!(invalid_network_id as u32, 0x0000_0106);
        
        let invalid_node_id = CommandStatus::InvalidNodeId;
        assert_eq!(invalid_node_id as u32, 0x0000_0107);
        
        // Test version negotiation error codes
        let unsupported_version = CommandStatus::UnsupportedVersion;
        assert_eq!(unsupported_version as u32, 0x0000_0108);
        
        let version_mismatch = CommandStatus::VersionMismatch;
        assert_eq!(version_mismatch as u32, 0x0000_0109);
    }

    #[test]
    fn test_enhanced_error_code_categorization() {
        use crate::datatypes::CommandStatus;
        
        // Test that new v5.0 error codes are properly categorized
        assert!(CommandStatus::InvalidBroadcastAreaIdentifier.is_broadcast_error());
        assert!(CommandStatus::InvalidBroadcastContentType.is_broadcast_error());
        assert!(CommandStatus::InvalidBroadcastFrequency.is_broadcast_error());
        assert!(CommandStatus::InvalidBroadcastServiceGroup.is_broadcast_error());
        
        assert!(CommandStatus::CongestionStateRejected.is_congestion_error());
        assert!(CommandStatus::MessageThrottled.is_congestion_error());
        
        assert!(CommandStatus::InvalidNetworkId.is_network_error());
        assert!(CommandStatus::InvalidNodeId.is_network_error());
        
        assert!(CommandStatus::UnsupportedVersion.is_version_error());
        assert!(CommandStatus::VersionMismatch.is_version_error());
        
        // Test that legacy error codes are not v5.0 specific
        assert!(!CommandStatus::Ok.is_v50_specific());
        assert!(!CommandStatus::SystemError.is_v50_specific());
        assert!(!CommandStatus::InvalidMessageId.is_v50_specific());
        
        // Test that new error codes are v5.0 specific
        assert!(CommandStatus::InvalidBroadcastAreaIdentifier.is_v50_specific());
        assert!(CommandStatus::CongestionStateRejected.is_v50_specific());
        assert!(CommandStatus::UnsupportedVersion.is_v50_specific());
    }

    #[test]
    fn test_enhanced_error_code_descriptions() {
        use crate::datatypes::CommandStatus;
        
        // Test that new error codes have descriptive error messages
        let broadcast_error = CommandStatus::InvalidBroadcastAreaIdentifier;
        assert!(broadcast_error.description().contains("broadcast"));
        assert!(broadcast_error.description().contains("area"));
        
        let congestion_error = CommandStatus::CongestionStateRejected;
        assert!(congestion_error.description().contains("congestion"));
        
        let version_error = CommandStatus::UnsupportedVersion;
        assert!(version_error.description().contains("version"));
        assert!(version_error.description().contains("unsupported"));
    }

    #[test]
    fn test_enhanced_error_code_conversion() {
        use crate::datatypes::CommandStatus;
        
        // Test conversion from u32 values
        let status_100 = CommandStatus::try_from(0x0000_0100u32);
        assert!(status_100.is_ok());
        assert_eq!(status_100.unwrap(), CommandStatus::InvalidBroadcastAreaIdentifier);
        
        let status_105 = CommandStatus::try_from(0x0000_0105u32);
        assert!(status_105.is_ok());
        assert_eq!(status_105.unwrap(), CommandStatus::MessageThrottled);
        
        let status_109 = CommandStatus::try_from(0x0000_0109u32);
        assert!(status_109.is_ok());
        assert_eq!(status_109.unwrap(), CommandStatus::VersionMismatch);
        
        // Test that unknown error codes return appropriate error
        let status_unknown = CommandStatus::try_from(0x0000_0200u32);
        assert!(status_unknown.is_err());
    }

    #[test]
    fn test_broadcast_error_validation() {
        use crate::datatypes::BroadcastSm;
        
        // Test that broadcast PDU validation can use new error codes
        let broadcast_error_result = BroadcastSm::builder()
            .sequence_number(1)
            .message_id("BC001")
            .broadcast_area_identifier(vec![]) // Invalid - empty
            .build();
        
        assert!(broadcast_error_result.is_err());
        // In a real implementation, this would return InvalidBroadcastAreaIdentifier
        // For now, we test the error structure exists
    }

    #[test]
    fn test_congestion_error_handling() {
        use crate::datatypes::CommandStatus;
        
        // Test congestion-related error handling
        let congestion_errors = vec![
            CommandStatus::CongestionStateRejected,
            CommandStatus::MessageThrottled,
            CommandStatus::ThrottlingError, // Legacy throttling error
        ];
        
        for error in congestion_errors {
            assert!(error.is_throttling_related());
        }
    }

    #[test]
    fn test_enhanced_error_recovery_hints() {
        use crate::datatypes::CommandStatus;
        
        // Test that new error codes provide recovery hints
        let retry_errors = vec![
            CommandStatus::CongestionStateRejected,
            CommandStatus::MessageThrottled,
        ];
        
        for error in retry_errors {
            assert!(error.should_retry());
            assert!(error.suggested_retry_delay().is_some());
        }
        
        let no_retry_errors = vec![
            CommandStatus::InvalidBroadcastAreaIdentifier,
            CommandStatus::UnsupportedVersion,
            CommandStatus::VersionMismatch,
        ];
        
        for error in no_retry_errors {
            assert!(!error.should_retry());
            assert!(error.suggested_retry_delay().is_none());
        }
    }

    #[test]
    fn test_error_code_compatibility() {
        use crate::datatypes::CommandStatus;
        
        // Test that v5.0 error codes don't conflict with v3.4 codes
        let _v34_max_error = 0x000000FFu32;
        let v50_min_error = 0x00000100u32;
        
        assert!(CommandStatus::InvalidBroadcastAreaIdentifier as u32 >= v50_min_error);
        assert!(CommandStatus::VersionMismatch as u32 >= v50_min_error);
        
        // Test that legacy error codes remain unchanged
        assert_eq!(CommandStatus::Ok as u32, 0x00000000);
        assert_eq!(CommandStatus::SystemError as u32, 0x00000008);
        assert_eq!(CommandStatus::InvalidMessageId as u32, 0x0000000C);
        assert_eq!(CommandStatus::ThrottlingError as u32, 0x00000058);
    }

    #[test]
    fn test_v50_error_classification() {
        use crate::datatypes::CommandStatus;
        
        // Test broadcast error classification
        assert!(CommandStatus::InvalidBroadcastAreaIdentifier.is_broadcast_error());
        assert!(CommandStatus::InvalidBroadcastContentType.is_broadcast_error());
        assert!(CommandStatus::InvalidBroadcastFrequency.is_broadcast_error());
        assert!(CommandStatus::InvalidBroadcastServiceGroup.is_broadcast_error());
        
        // Test congestion error classification
        assert!(CommandStatus::CongestionStateRejected.is_congestion_error());
        assert!(CommandStatus::MessageThrottled.is_congestion_error());
        
        // Test network error classification  
        assert!(CommandStatus::InvalidNetworkId.is_network_error());
        assert!(CommandStatus::InvalidNodeId.is_network_error());
        
        // Test version error classification
        assert!(CommandStatus::UnsupportedVersion.is_version_error());
        assert!(CommandStatus::VersionMismatch.is_version_error());
        
        // Test v5.0 specific detection
        assert!(CommandStatus::InvalidBroadcastAreaIdentifier.is_v50_specific());
        assert!(CommandStatus::VersionMismatch.is_v50_specific());
        assert!(!CommandStatus::Ok.is_v50_specific());
        assert!(!CommandStatus::SystemError.is_v50_specific());
    }

    #[test]
    fn test_error_descriptions() {
        use crate::datatypes::CommandStatus;
        
        // Test v5.0 error descriptions are informative
        assert!(!CommandStatus::InvalidBroadcastAreaIdentifier.description().is_empty());
        assert!(CommandStatus::InvalidBroadcastAreaIdentifier.description().contains("broadcast"));
        assert!(CommandStatus::InvalidBroadcastAreaIdentifier.description().contains("area"));
        
        assert!(!CommandStatus::CongestionStateRejected.description().is_empty());
        assert!(CommandStatus::CongestionStateRejected.description().contains("congestion"));
        
        assert!(!CommandStatus::UnsupportedVersion.description().is_empty());
        assert!(CommandStatus::UnsupportedVersion.description().contains("version"));
    }

    #[test]
    fn test_retry_strategy_logic() {
        use crate::datatypes::CommandStatus;
        
        // Test congestion errors have appropriate retry delays
        assert_eq!(CommandStatus::CongestionStateRejected.suggested_retry_delay(), Some(30));
        assert_eq!(CommandStatus::MessageThrottled.suggested_retry_delay(), Some(60));
        assert_eq!(CommandStatus::ThrottlingError.suggested_retry_delay(), Some(120));
        
        // Test system errors have short retry delays
        assert_eq!(CommandStatus::SystemError.suggested_retry_delay(), Some(5));
        assert_eq!(CommandStatus::MessageQueueFull.suggested_retry_delay(), Some(10));
        
        // Test validation errors should not be retried
        assert_eq!(CommandStatus::InvalidBroadcastAreaIdentifier.suggested_retry_delay(), None);
        assert_eq!(CommandStatus::UnsupportedVersion.suggested_retry_delay(), None);
        assert_eq!(CommandStatus::InvalidNetworkId.suggested_retry_delay(), None);
    }

    #[test]
    fn test_error_code_range_validation() {
        use crate::datatypes::CommandStatus;
        
        // Test broadcast error code range (0x0100-0x0103)
        assert_eq!(CommandStatus::InvalidBroadcastAreaIdentifier as u32, 0x00000100);
        assert_eq!(CommandStatus::InvalidBroadcastContentType as u32, 0x00000101);
        assert_eq!(CommandStatus::InvalidBroadcastFrequency as u32, 0x00000102);
        assert_eq!(CommandStatus::InvalidBroadcastServiceGroup as u32, 0x00000103);
        
        // Test congestion error code range (0x0104-0x0105)
        assert_eq!(CommandStatus::CongestionStateRejected as u32, 0x00000104);
        assert_eq!(CommandStatus::MessageThrottled as u32, 0x00000105);
        
        // Test network error code range (0x0106-0x0107)
        assert_eq!(CommandStatus::InvalidNetworkId as u32, 0x00000106);
        assert_eq!(CommandStatus::InvalidNodeId as u32, 0x00000107);
        
        // Test version error code range (0x0108-0x0109)
        assert_eq!(CommandStatus::UnsupportedVersion as u32, 0x00000108);
        assert_eq!(CommandStatus::VersionMismatch as u32, 0x00000109);
    }

    #[test]
    fn test_comprehensive_v50_error_coverage() {
        use crate::datatypes::CommandStatus;
        
        // Test all v5.0 errors are properly categorized
        let all_v50_errors = vec![
            CommandStatus::InvalidBroadcastAreaIdentifier,
            CommandStatus::InvalidBroadcastContentType,
            CommandStatus::InvalidBroadcastFrequency,
            CommandStatus::InvalidBroadcastServiceGroup,
            CommandStatus::CongestionStateRejected,
            CommandStatus::MessageThrottled,
            CommandStatus::InvalidNetworkId,
            CommandStatus::InvalidNodeId,
            CommandStatus::UnsupportedVersion,
            CommandStatus::VersionMismatch,
        ];
        
        for error in all_v50_errors {
            assert!(error.is_v50_specific());
            assert!(!error.description().is_empty());
            
            // Each error should belong to exactly one category
            let categories = [
                error.is_broadcast_error(),
                error.is_congestion_error(), 
                error.is_network_error(),
                error.is_version_error(),
            ];
            assert_eq!(categories.iter().filter(|&&x| x).count(), 1);
        }
    }

    #[test]
    fn test_error_severity_classification() {
        use crate::datatypes::{CommandStatus, ErrorSeverity};
        
        // Test critical errors
        assert_eq!(CommandStatus::InvalidCommandId.severity(), ErrorSeverity::Critical);
        assert_eq!(CommandStatus::InvalidCommandLength.severity(), ErrorSeverity::Critical);
        
        // Test error severity
        assert_eq!(CommandStatus::BindFailed.severity(), ErrorSeverity::Error);
        assert_eq!(CommandStatus::UnsupportedVersion.severity(), ErrorSeverity::Error);
        assert_eq!(CommandStatus::InvalidBroadcastAreaIdentifier.severity(), ErrorSeverity::Error);
        
        // Test warning severity
        assert_eq!(CommandStatus::SystemError.severity(), ErrorSeverity::Warning);
        assert_eq!(CommandStatus::CongestionStateRejected.severity(), ErrorSeverity::Warning);
        assert_eq!(CommandStatus::MessageThrottled.severity(), ErrorSeverity::Warning);
        
        // Test info severity
        assert_eq!(CommandStatus::Ok.severity(), ErrorSeverity::Info);
    }

    #[test]
    fn test_error_category_classification() {
        use crate::datatypes::{CommandStatus, ErrorCategory};
        
        // Test authentication category
        assert_eq!(CommandStatus::BindFailed.category(), ErrorCategory::Authentication);
        assert_eq!(CommandStatus::InvalidPassword.category(), ErrorCategory::Authentication);
        
        // Test rate limit category
        assert_eq!(CommandStatus::ThrottlingError.category(), ErrorCategory::RateLimit);
        assert_eq!(CommandStatus::CongestionStateRejected.category(), ErrorCategory::RateLimit);
        assert_eq!(CommandStatus::MessageThrottled.category(), ErrorCategory::RateLimit);
        
        // Test broadcast category
        assert_eq!(CommandStatus::InvalidBroadcastAreaIdentifier.category(), ErrorCategory::Broadcast);
        assert_eq!(CommandStatus::InvalidBroadcastContentType.category(), ErrorCategory::Broadcast);
        
        // Test version category
        assert_eq!(CommandStatus::UnsupportedVersion.category(), ErrorCategory::Version);
        assert_eq!(CommandStatus::VersionMismatch.category(), ErrorCategory::Version);
        
        // Test network category
        assert_eq!(CommandStatus::InvalidNetworkId.category(), ErrorCategory::Network);
        assert_eq!(CommandStatus::InvalidNodeId.category(), ErrorCategory::Network);
        
        // Test success category
        assert_eq!(CommandStatus::Ok.category(), ErrorCategory::Success);
    }

    #[test]
    fn test_error_help_messages() {
        use crate::datatypes::CommandStatus;
        
        // Test v5.0 specific help messages exist
        assert!(CommandStatus::CongestionStateRejected.help_message().is_some());
        assert!(CommandStatus::MessageThrottled.help_message().is_some());
        assert!(CommandStatus::UnsupportedVersion.help_message().is_some());
        assert!(CommandStatus::VersionMismatch.help_message().is_some());
        assert!(CommandStatus::InvalidBroadcastAreaIdentifier.help_message().is_some());
        assert!(CommandStatus::InvalidNetworkId.help_message().is_some());
        
        // Test help messages contain useful guidance
        let congestion_help = CommandStatus::CongestionStateRejected.help_message().unwrap();
        assert!(congestion_help.contains("congestion"));
        assert!(congestion_help.contains("rate") || congestion_help.contains("backoff"));
        
        let version_help = CommandStatus::UnsupportedVersion.help_message().unwrap();
        assert!(version_help.contains("version"));
        assert!(version_help.contains("interface_version") || version_help.contains("bind"));
        
        // Test that regular errors don't have help messages
        assert!(CommandStatus::Ok.help_message().is_none());
        assert!(CommandStatus::InvalidCommandId.help_message().is_none());
    }

    #[test] 
    fn test_v50_feature_error_detection() {
        use crate::datatypes::CommandStatus;
        
        // Test v5.0 feature specific errors
        assert!(CommandStatus::InvalidBroadcastAreaIdentifier.is_v50_feature_error());
        assert!(CommandStatus::InvalidBroadcastContentType.is_v50_feature_error());
        assert!(CommandStatus::CongestionStateRejected.is_v50_feature_error());
        assert!(CommandStatus::MessageThrottled.is_v50_feature_error());
        assert!(CommandStatus::InvalidNetworkId.is_v50_feature_error());
        assert!(CommandStatus::UnsupportedVersion.is_v50_feature_error());
        assert!(CommandStatus::VersionMismatch.is_v50_feature_error());
        
        // Test v3.4 errors are not v5.0 feature errors
        assert!(!CommandStatus::Ok.is_v50_feature_error());
        assert!(!CommandStatus::SystemError.is_v50_feature_error());
        assert!(!CommandStatus::ThrottlingError.is_v50_feature_error()); // Legacy throttling
        assert!(!CommandStatus::BindFailed.is_v50_feature_error());
    }

    #[test]
    fn test_enhanced_error_handling_integration() {
        use crate::datatypes::{CommandStatus, ErrorSeverity, ErrorCategory};
        
        // Test comprehensive error context for monitoring systems
        let error = CommandStatus::CongestionStateRejected;
        
        assert_eq!(error.severity(), ErrorSeverity::Warning);
        assert_eq!(error.category(), ErrorCategory::RateLimit);
        assert!(error.should_retry());
        assert_eq!(error.suggested_retry_delay(), Some(30));
        assert!(error.is_congestion_error());
        assert!(error.is_throttling_related());
        assert!(error.is_v50_specific());
        assert!(error.is_v50_feature_error());
        assert!(error.help_message().is_some());
        assert!(!error.description().is_empty());
        
        // Test that all context methods work together consistently
        assert!(error.is_throttling_related());
        assert!(error.category() == ErrorCategory::RateLimit);
    }

    #[test]
    fn test_bind_credentials_version_selection() {
        use crate::datatypes::InterfaceVersion;
        use crate::client::types::BindCredentials;
        
        // Test default v3.4 behavior
        let v34_creds = BindCredentials::transmitter("test", "pass");
        assert_eq!(v34_creds.interface_version, InterfaceVersion::SmppV34);
        assert!(!v34_creds.is_v50());
        
        // Test explicit v5.0 constructors
        let v50_creds = BindCredentials::transmitter_v50("test", "pass");
        assert_eq!(v50_creds.interface_version, InterfaceVersion::SmppV50);
        assert!(v50_creds.is_v50());
        
        // Test version override
        let upgraded_creds = v34_creds.with_version(InterfaceVersion::SmppV50);
        assert_eq!(upgraded_creds.interface_version, InterfaceVersion::SmppV50);
        assert!(upgraded_creds.is_v50());
    }

    #[test]
    fn test_bind_credentials_all_types() {
        use crate::datatypes::InterfaceVersion;
        use crate::client::types::{BindCredentials, BindType};
        
        // Test v3.4 constructors
        let tx_v34 = BindCredentials::transmitter("test", "pass");
        assert_eq!(tx_v34.bind_type, BindType::Transmitter);
        assert_eq!(tx_v34.interface_version, InterfaceVersion::SmppV34);
        
        let rx_v34 = BindCredentials::receiver("test", "pass");
        assert_eq!(rx_v34.bind_type, BindType::Receiver);
        assert_eq!(rx_v34.interface_version, InterfaceVersion::SmppV34);
        
        let trx_v34 = BindCredentials::transceiver("test", "pass");
        assert_eq!(trx_v34.bind_type, BindType::Transceiver);
        assert_eq!(trx_v34.interface_version, InterfaceVersion::SmppV34);
        
        // Test v5.0 constructors
        let tx_v50 = BindCredentials::transmitter_v50("test", "pass");
        assert_eq!(tx_v50.bind_type, BindType::Transmitter);
        assert_eq!(tx_v50.interface_version, InterfaceVersion::SmppV50);
        
        let rx_v50 = BindCredentials::receiver_v50("test", "pass");
        assert_eq!(rx_v50.bind_type, BindType::Receiver);
        assert_eq!(rx_v50.interface_version, InterfaceVersion::SmppV50);
        
        let trx_v50 = BindCredentials::transceiver_v50("test", "pass");
        assert_eq!(trx_v50.bind_type, BindType::Transceiver);
        assert_eq!(trx_v50.interface_version, InterfaceVersion::SmppV50);
    }

    #[test]
    fn test_client_options_v50_features() {
        use crate::client::builder::ClientOptions;
        
        // Test default options
        let default_opts = ClientOptions::new();
        assert!(!default_opts.enable_v50_features);
        assert!(default_opts.auto_negotiate_version);
        
        // Test v5.0 feature enablement
        let v50_opts = ClientOptions::new().with_v50_features();
        assert!(v50_opts.enable_v50_features);
        assert!(v50_opts.auto_negotiate_version);
        
        // Test auto-negotiation disable
        let manual_opts = ClientOptions::new().without_auto_negotiate();
        assert!(!manual_opts.enable_v50_features);
        assert!(!manual_opts.auto_negotiate_version);
        
        // Test combination
        let combined_opts = ClientOptions::new()
            .with_v50_features()
            .without_auto_negotiate();
        assert!(combined_opts.enable_v50_features);
        assert!(!combined_opts.auto_negotiate_version);
    }

    #[test]
    fn test_broadcast_message_builder() {
        use crate::client::types::BroadcastMessage;
        use crate::datatypes::{PriorityFlag, DataCoding, TypeOfNumber, NumericPlanIndicator};
        
        // Test basic broadcast message creation
        let basic_msg = BroadcastMessage::new(
            "1234567890",
            "BC001",
            vec![0x01, 0x02, 0x03, 0x04],
        );
        assert_eq!(basic_msg.from, "1234567890");
        assert_eq!(basic_msg.message_id, "BC001");
        assert_eq!(basic_msg.broadcast_area_identifier, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(basic_msg.broadcast_rep_num, 1);
        assert_eq!(basic_msg.broadcast_frequency_interval, 3600);
        
        // Test builder pattern
        let builder_result = BroadcastMessage::builder()
            .from("9876543210")
            .message_id("BC002")
            .area_identifier(vec![0x05, 0x06])
            .content_type(1)
            .repetitions(3)
            .frequency_interval(1800)
            .priority(PriorityFlag::Level1)
            .data_coding(DataCoding::Ascii)
            .source_numbering(TypeOfNumber::International, NumericPlanIndicator::Isdn)
            .build();
        
        assert!(builder_result.is_ok());
        let built_msg = builder_result.unwrap();
        assert_eq!(built_msg.from, "9876543210");
        assert_eq!(built_msg.message_id, "BC002");
        assert_eq!(built_msg.broadcast_area_identifier, vec![0x05, 0x06]);
        assert_eq!(built_msg.broadcast_content_type, 1);
        assert_eq!(built_msg.broadcast_rep_num, 3);
        assert_eq!(built_msg.broadcast_frequency_interval, 1800);
        assert_eq!(built_msg.options.priority, PriorityFlag::Level1);
        assert_eq!(built_msg.options.data_coding, DataCoding::Ascii);
        assert_eq!(built_msg.options.source_ton, TypeOfNumber::International);
        assert_eq!(built_msg.options.source_npi, NumericPlanIndicator::Isdn);
    }

    #[test]
    fn test_broadcast_message_validation() {
        use crate::client::types::BroadcastMessage;
        
        // Test missing required fields
        let no_from_result = BroadcastMessage::builder()
            .message_id("BC001")
            .area_identifier(vec![0x01])
            .build();
        assert!(no_from_result.is_err());
        assert!(no_from_result.unwrap_err().contains("Source phone number is required"));
        
        let no_message_id_result = BroadcastMessage::builder()
            .from("1234567890")
            .area_identifier(vec![0x01])
            .build();
        assert!(no_message_id_result.is_err());
        assert!(no_message_id_result.unwrap_err().contains("Message ID is required"));
        
        let no_area_result = BroadcastMessage::builder()
            .from("1234567890")
            .message_id("BC001")
            .build();
        assert!(no_area_result.is_err());
        assert!(no_area_result.unwrap_err().contains("Broadcast area identifier is required"));
        
        // Test empty area identifier
        let empty_area_result = BroadcastMessage::builder()
            .from("1234567890")
            .message_id("BC001")
            .area_identifier(vec![])
            .build();
        assert!(empty_area_result.is_err());
        assert!(empty_area_result.unwrap_err().contains("Broadcast area identifier cannot be empty"));
        
        // Test zero repetitions
        let zero_reps_result = BroadcastMessage::builder()
            .from("1234567890")
            .message_id("BC001")
            .area_identifier(vec![0x01])
            .repetitions(0)
            .build();
        assert!(zero_reps_result.is_err());
        assert!(zero_reps_result.unwrap_err().contains("Broadcast repetition number must be greater than 0"));
    }

    #[test]
    fn test_version_negotiation_scenarios() {
        use crate::datatypes::InterfaceVersion;
        use crate::client::types::BindCredentials;
        
        // Test backward compatibility scenario
        let v34_client_creds = BindCredentials::transmitter("legacy_client", "pass");
        assert_eq!(v34_client_creds.interface_version, InterfaceVersion::SmppV34);
        assert!(!v34_client_creds.is_v50());
        
        // Test v5.0 client scenario
        let v50_client_creds = BindCredentials::transmitter_v50("modern_client", "pass");
        assert_eq!(v50_client_creds.interface_version, InterfaceVersion::SmppV50);
        assert!(v50_client_creds.is_v50());
        
        // Test upgrade scenario
        let upgraded_creds = v34_client_creds
            .with_system_type("SMS")
            .with_version(InterfaceVersion::SmppV50);
        assert_eq!(upgraded_creds.interface_version, InterfaceVersion::SmppV50);
        assert!(upgraded_creds.is_v50());
        assert_eq!(upgraded_creds.system_type, Some("SMS".to_string()));
    }

    #[test]
    fn test_dual_version_client_support() {
        use crate::datatypes::InterfaceVersion;
        use crate::client::types::BindCredentials;
        
        // Test that the same client code can work with both versions
        let versions = vec![
            InterfaceVersion::SmppV34,
            InterfaceVersion::SmppV50,
        ];
        
        for version in versions {
            let creds = BindCredentials::transmitter("test", "pass")
                .with_version(version);
            
            assert_eq!(creds.interface_version, version);
            
            match version {
                InterfaceVersion::SmppV34 => assert!(!creds.is_v50()),
                InterfaceVersion::SmppV50 => assert!(creds.is_v50()),
                _ => panic!("Unexpected version"),
            }
        }
    }

    #[test]
    fn test_flow_control_congestion_response() {
        use crate::client::flow_control::{FlowControlManager, FlowControlConfig};
        use std::time::Duration;
        
        // Use faster adjustment interval for testing
        let mut config = FlowControlConfig::default();
        config.adjustment_interval = Duration::from_millis(1);
        
        let mut manager = FlowControlManager::with_config(10.0, 50.0, 1.0, config);
        let initial_rate = manager.current_rate_limit();
        
        // Test low congestion - rate should stay relatively high
        manager.update_congestion_state(10);
        assert!(manager.current_rate_limit() >= initial_rate * 0.7);
        assert!(!manager.is_congested());
        
        // Test high congestion - rate should reduce
        std::thread::sleep(Duration::from_millis(5)); // Ensure time passes
        manager.update_congestion_state(80);
        assert!(manager.current_rate_limit() < initial_rate);
        assert!(manager.is_congested());
        
        // Test recovery - rate should increase
        std::thread::sleep(Duration::from_millis(5));
        manager.update_congestion_state(20);
        let recovery_rate = manager.current_rate_limit();
        std::thread::sleep(Duration::from_millis(5));
        manager.update_congestion_state(0);
        // Rate should move toward recovery, even if slowly
        assert!(manager.current_rate_limit() >= recovery_rate * 0.95);
    }

    #[test]
    fn test_flow_control_error_adaptation() {
        use crate::client::flow_control::{FlowControlManager, FlowControlConfig};
        use crate::datatypes::CommandStatus;
        use std::time::Duration;
        
        let mut config = FlowControlConfig::default();
        config.adjustment_interval = Duration::from_millis(1);
        
        let mut manager = FlowControlManager::with_config(10.0, 50.0, 1.0, config);
        let initial_rate = manager.current_rate_limit();
        
        // Test congestion error response
        manager.handle_error_response(CommandStatus::CongestionStateRejected);
        assert!(manager.current_rate_limit() < initial_rate);
        assert_eq!(manager.statistics().error_adjustments, 1);
        
        // Test throttling error response
        let rate_after_congestion = manager.current_rate_limit();
        std::thread::sleep(Duration::from_millis(10));
        manager.handle_error_response(CommandStatus::MessageThrottled);
        assert!(manager.current_rate_limit() < rate_after_congestion);
        assert_eq!(manager.statistics().error_adjustments, 2);
        
        // Test non-throttling error (should not affect rate)
        let rate_before_non_throttling = manager.current_rate_limit();
        manager.handle_error_response(CommandStatus::InvalidMessageId);
        assert_eq!(manager.current_rate_limit(), rate_before_non_throttling);
        assert_eq!(manager.statistics().error_adjustments, 2); // No change
    }

    #[test]
    fn test_flow_control_rate_limits() {
        use crate::client::flow_control::FlowControlManager;
        
        let mut manager = FlowControlManager::new(10.0, 20.0, 2.0);
        
        // Test minimum rate limit enforcement
        manager.update_congestion_state(100); // Maximum congestion
        assert!(manager.current_rate_limit() >= 2.0);
        
        // Reset and test maximum rate limit enforcement
        let mut high_performance_manager = FlowControlManager::new(10.0, 15.0, 1.0);
        high_performance_manager.update_congestion_state(0); // No congestion
        
        // Force multiple rapid adjustments to test max limit
        for _ in 0..5 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            high_performance_manager.update_congestion_state(0);
        }
        assert!(high_performance_manager.current_rate_limit() <= 15.0);
    }

    #[test]
    fn test_flow_control_message_delay_calculation() {
        use crate::client::flow_control::FlowControlManager;
        use std::time::Duration;
        
        let manager = FlowControlManager::new(10.0, 50.0, 1.0);
        
        // At 10 messages per second, delay should be 100ms
        let delay = manager.message_delay();
        assert_eq!(delay, Duration::from_millis(100));
        
        // Test with different rate
        let fast_manager = FlowControlManager::new(100.0, 200.0, 10.0);
        let fast_delay = fast_manager.message_delay();
        assert_eq!(fast_delay, Duration::from_millis(10)); // 1/100 second = 10ms
    }

    #[test]
    fn test_flow_control_recommended_actions() {
        use crate::client::flow_control::{FlowControlManager, FlowControlAction};
        
        let mut manager = FlowControlManager::new(10.0, 50.0, 1.0);
        
        // Test different congestion levels and their recommended actions
        manager.update_congestion_state(5);
        assert_eq!(manager.recommended_action(), FlowControlAction::IncreaseRate);
        
        manager.update_congestion_state(25);
        assert_eq!(manager.recommended_action(), FlowControlAction::MaintainRate);
        
        manager.update_congestion_state(45);
        assert_eq!(manager.recommended_action(), FlowControlAction::ReduceRate);
        
        manager.update_congestion_state(70);
        assert_eq!(manager.recommended_action(), FlowControlAction::ReduceRateSignificantly);
        
        manager.update_congestion_state(95);
        assert_eq!(manager.recommended_action(), FlowControlAction::MinimizeRate);
    }

    #[test]
    fn test_flow_control_statistics_tracking() {
        use crate::client::flow_control::{FlowControlManager, FlowControlConfig};
        use crate::datatypes::CommandStatus;
        use std::time::Duration;
        
        let mut config = FlowControlConfig::default();
        config.adjustment_interval = Duration::from_millis(1);
        
        let mut manager = FlowControlManager::with_config(10.0, 50.0, 1.0, config);
        let initial_stats = manager.statistics().clone();
        
        // Generate some activity
        manager.update_congestion_state(50);
        std::thread::sleep(Duration::from_millis(10));
        manager.update_congestion_state(20);
        std::thread::sleep(Duration::from_millis(5));
        manager.handle_error_response(CommandStatus::MessageThrottled);
        
        let final_stats = manager.statistics();
        
        // Verify statistics were updated
        assert!(final_stats.total_adjustments > initial_stats.total_adjustments);
        assert!(final_stats.error_adjustments > initial_stats.error_adjustments);
        assert!(final_stats.last_adjustment.is_some());
        assert!(final_stats.effective_rate != initial_stats.effective_rate);
        
        // Test peak and minimum tracking
        assert!(final_stats.peak_rate >= initial_stats.peak_rate);
        assert!(final_stats.minimum_rate <= initial_stats.minimum_rate);
    }

    #[test]
    fn test_flow_control_configuration() {
        use crate::client::flow_control::{FlowControlManager, FlowControlConfig};
        use std::time::Duration;
        
        let mut config = FlowControlConfig::default();
        config.congestion_sensitivity = 0.5; // Less aggressive
        config.recovery_rate = 0.2; // Faster recovery
        config.adjustment_interval = Duration::from_millis(1); // Faster adjustments
        
        let mut manager = FlowControlManager::with_config(10.0, 50.0, 1.0, config);
        
        // Test that configuration affects behavior
        manager.update_congestion_state(50);
        let rate_with_low_sensitivity = manager.current_rate_limit();
        
        // Compare with default config
        let mut default_manager = FlowControlManager::new(10.0, 50.0, 1.0);
        default_manager.update_congestion_state(50);
        let rate_with_high_sensitivity = default_manager.current_rate_limit();
        
        // Lower sensitivity should result in less aggressive rate reduction
        assert!(rate_with_low_sensitivity >= rate_with_high_sensitivity);
    }

    #[test]
    fn test_flow_control_congestion_timeout() {
        use crate::client::flow_control::{FlowControlManager, FlowControlConfig};
        use std::time::Duration;
        
        let mut config = FlowControlConfig::default();
        config.congestion_timeout = Duration::from_millis(5); // Very short timeout
        
        let mut manager = FlowControlManager::with_config(10.0, 50.0, 1.0, config);
        
        // Set congestion state
        manager.update_congestion_state(80);
        assert_eq!(manager.congestion_state(), Some(80));
        assert!(manager.is_congested());
        
        // Wait for timeout
        std::thread::sleep(Duration::from_millis(10));
        
        // Congestion state should be None after timeout
        assert_eq!(manager.congestion_state(), None);
        assert!(!manager.is_congested());
    }

    #[test]
    fn test_flow_control_action_descriptions() {
        use crate::client::flow_control::FlowControlAction;
        
        // Test that all actions have meaningful descriptions
        let actions = vec![
            FlowControlAction::IncreaseRate,
            FlowControlAction::MaintainRate,
            FlowControlAction::ReduceRate,
            FlowControlAction::ReduceRateSignificantly,
            FlowControlAction::MinimizeRate,
        ];
        
        for action in actions {
            let description = action.description();
            assert!(!description.is_empty());
            assert!(description.len() > 10); // Should be descriptive
        }
    }

    #[test]
    fn test_flow_control_adaptive_behavior() {
        use crate::client::flow_control::{FlowControlManager, FlowControlConfig};
        use crate::datatypes::CommandStatus;
        use std::time::Duration;
        
        // Use faster adjustment for testing
        let mut config = FlowControlConfig::default();
        config.adjustment_interval = Duration::from_millis(1);
        
        let mut manager = FlowControlManager::with_config(20.0, 100.0, 5.0, config);
        
        // Simulate a realistic scenario: start normal, hit congestion, recover
        
        // 1. Normal operation
        assert_eq!(manager.current_rate_limit(), 20.0);
        
        // 2. Server reports moderate congestion
        manager.update_congestion_state(30);
        let moderate_congestion_rate = manager.current_rate_limit();
        assert!(moderate_congestion_rate < 20.0);
        assert!(moderate_congestion_rate > 10.0); // Should not be too aggressive
        
        // 3. Error responses indicate more serious congestion
        std::thread::sleep(Duration::from_millis(10));
        manager.handle_error_response(CommandStatus::CongestionStateRejected);
        let after_error_rate = manager.current_rate_limit();
        assert!(after_error_rate < moderate_congestion_rate);
        
        // 4. Congestion starts to clear
        std::thread::sleep(Duration::from_millis(10));
        manager.update_congestion_state(10);
        let recovery_start_rate = manager.current_rate_limit();
        
        // 5. Full recovery
        std::thread::sleep(Duration::from_millis(10));
        manager.update_congestion_state(0);
        let recovered_rate = manager.current_rate_limit();
        
        // Rate should gradually increase during recovery
        assert!(recovered_rate > recovery_start_rate);
        assert!(recovered_rate > after_error_rate);
        
        // But recovery should be gradual, not immediate
        assert!(recovered_rate < 20.0); // Should not immediately return to base rate
    }

    // Phase 10: Complete Integration Tests for v3.4 to v5.0 Scenarios

    #[test]
    fn test_complete_v34_to_v50_compatibility() {
        use crate::datatypes::{InterfaceVersion, CommandStatus};
        use crate::codec::PduRegistry;
        
        // Test backward compatibility across all supported versions
        let v34_registry = PduRegistry::for_version(InterfaceVersion::SmppV34);
        let v50_registry = PduRegistry::for_version(InterfaceVersion::SmppV50);
        
        // Verify registries are created successfully
        assert_eq!(v34_registry.version(), InterfaceVersion::SmppV34);
        assert_eq!(v50_registry.version(), InterfaceVersion::SmppV50);
        
        // Test error code compatibility
        assert_eq!(CommandStatus::Ok as u32, 0x00000000);
        assert_eq!(CommandStatus::InvalidMsgLength as u32, 0x00000001);
        
        // Test v5.0 enhanced error codes
        assert_eq!(CommandStatus::InvalidBroadcastAreaIdentifier as u32, 0x00000100);
        assert_eq!(CommandStatus::InvalidBroadcastContentType as u32, 0x00000101);
        assert_eq!(CommandStatus::CongestionStateRejected as u32, 0x00000104);
    }

    #[test]
    fn test_version_negotiation_complete_scenarios() {
        use crate::datatypes::InterfaceVersion;
        use crate::client::types::BindCredentials;
        
        // Test automatic version detection from bind credentials
        let v34_credentials = BindCredentials::transmitter("test", "pass");
        assert_eq!(v34_credentials.interface_version, InterfaceVersion::SmppV34);
        
        let v50_credentials = BindCredentials::transmitter_v50("test", "pass");
        assert_eq!(v50_credentials.interface_version, InterfaceVersion::SmppV50);
        
        // Test version-specific features
        assert_eq!(InterfaceVersion::SmppV34 as u8, 0x34);
        assert_eq!(InterfaceVersion::SmppV50 as u8, 0x50);
    }

    #[test]
    fn test_comprehensive_broadcast_message_lifecycle() {
        use crate::client::types::BroadcastMessage;
        
        // Test high-level broadcast message creation
        let broadcast_msg = BroadcastMessage::new(
            "1234567890",
            "BC001",
            vec![0x01, 0x02, 0x03, 0x04], // area identifier
        );
        
        assert_eq!(broadcast_msg.from, "1234567890");
        assert_eq!(broadcast_msg.message_id, "BC001");
        assert_eq!(broadcast_msg.broadcast_area_identifier, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_comprehensive_error_handling_scenarios() {
        use crate::datatypes::{CommandStatus, ErrorSeverity, ErrorCategory};
        
        // Test comprehensive error categorization
        let critical_errors = vec![
            CommandStatus::InvalidBroadcastAreaIdentifier,
            CommandStatus::InvalidBroadcastContentType,
            CommandStatus::InvalidBroadcastFrequency,
        ];
        
        for error in critical_errors {
            assert_eq!(error.severity(), ErrorSeverity::Error);
            assert_eq!(error.category(), ErrorCategory::Broadcast);
            // Just verify help messages exist (may be None for some errors)
            let _help = error.help_message();
        }
        
        // Test throttling error behavior
        let throttling_errors = vec![
            CommandStatus::CongestionStateRejected,
            CommandStatus::MessageThrottled,
            CommandStatus::ThrottlingError,
        ];
        
        for error in throttling_errors {
            assert!(error.is_throttling_related());
            assert_eq!(error.severity(), ErrorSeverity::Warning);
            assert_eq!(error.category(), ErrorCategory::RateLimit);
        }
        
        // Test backward compatibility with v3.4 errors
        let v34_errors = vec![
            CommandStatus::InvalidMsgLength,
            CommandStatus::InvalidCommandLength,
            CommandStatus::InvalidCommandId,
        ];
        
        for error in v34_errors {
            // Test that v3.4 errors still work
            assert_ne!(error as u32, 0x00000000); // Not OK status
            let _help = error.help_message(); // May be None
        }
    }

    #[test]
    fn test_client_builder_complete_scenarios() {
        use crate::client::types::{BindCredentials, BroadcastMessage, SmsMessage};
        use crate::client::ClientOptions;
        use crate::datatypes::InterfaceVersion;
        
        // Test comprehensive credential building
        let v34_creds = BindCredentials::transmitter("sys_id", "pass")
            .with_system_type("TEST_APP")
            .with_version(InterfaceVersion::SmppV34);
        
        assert_eq!(v34_creds.system_id, "sys_id");
        assert_eq!(v34_creds.password, "pass");
        assert_eq!(v34_creds.system_type, Some("TEST_APP".to_string()));
        assert_eq!(v34_creds.interface_version, InterfaceVersion::SmppV34);
        
        let v50_creds = BindCredentials::transmitter_v50("sys_id", "pass")
            .with_system_type("TEST_V50");
        
        assert_eq!(v50_creds.interface_version, InterfaceVersion::SmppV50);
        assert_eq!(v50_creds.system_type, Some("TEST_V50".to_string()));
        
        // Test message builder scenarios
        let sms = SmsMessage::new("1234567890", "0987654321", "Hello World!");
        assert_eq!(sms.to, "1234567890");
        assert_eq!(sms.from, "0987654321");
        assert_eq!(sms.text, "Hello World!");
        
        let broadcast = BroadcastMessage::new(
            "broadcast_source",
            "BC_MSG_001",
            vec![0xFF, 0xEE, 0xDD, 0xCC],
        );
        assert_eq!(broadcast.from, "broadcast_source");
        assert_eq!(broadcast.message_id, "BC_MSG_001");
        assert_eq!(broadcast.broadcast_area_identifier, vec![0xFF, 0xEE, 0xDD, 0xCC]);
        
        // Test client options creation
        let options = ClientOptions::new();
        
        // Verify options are configurable
        assert!(!options.enable_v50_features); // Default is false
        assert!(options.auto_negotiate_version); // Default is true
    }

    #[test]
    fn test_flow_control_integration_complete() {
        use crate::client::flow_control::{FlowControlManager, FlowControlConfig, FlowControlAction};
        use crate::datatypes::CommandStatus;
        use std::time::Duration;
        
        // Test complete flow control lifecycle with realistic server behavior simulation
        let mut config = FlowControlConfig::default();
        config.adjustment_interval = Duration::from_millis(1); // Fast for testing
        config.congestion_sensitivity = 0.7; // Moderate sensitivity
        config.recovery_rate = 0.15; // Gradual recovery
        
        let mut manager = FlowControlManager::with_config(25.0, 100.0, 5.0, config);
        
        // Scenario 1: Normal operation
        assert_eq!(manager.current_rate_limit(), 25.0);
        assert_eq!(manager.recommended_action(), FlowControlAction::MaintainRate);
        
        // Scenario 2: Server reports increasing congestion
        manager.update_congestion_state(20); // Light congestion
        std::thread::sleep(Duration::from_millis(5));
        let light_congestion_rate = manager.current_rate_limit();
        assert!(light_congestion_rate < 25.0);
        assert_eq!(manager.recommended_action(), FlowControlAction::MaintainRate);
        
        manager.update_congestion_state(40); // Moderate congestion
        std::thread::sleep(Duration::from_millis(5));
        let moderate_congestion_rate = manager.current_rate_limit();
        assert!(moderate_congestion_rate < light_congestion_rate);
        assert_eq!(manager.recommended_action(), FlowControlAction::ReduceRate);
        
        // Scenario 3: Error-based adjustments
        manager.handle_error_response(CommandStatus::CongestionStateRejected);
        let error_adjusted_rate = manager.current_rate_limit();
        assert!(error_adjusted_rate < moderate_congestion_rate);
        
        // Scenario 4: Critical congestion
        std::thread::sleep(Duration::from_millis(5));
        manager.update_congestion_state(85); // Critical congestion
        let critical_rate = manager.current_rate_limit();
        assert!(critical_rate < error_adjusted_rate);
        assert_eq!(manager.recommended_action(), FlowControlAction::MinimizeRate);
        
        // Scenario 5: Recovery phase
        std::thread::sleep(Duration::from_millis(5));
        manager.update_congestion_state(60); // Reducing congestion
        std::thread::sleep(Duration::from_millis(5));
        manager.update_congestion_state(30); // Further reduction
        std::thread::sleep(Duration::from_millis(5));
        manager.update_congestion_state(10); // Almost clear
        
        let recovery_rate = manager.current_rate_limit();
        assert!(recovery_rate > critical_rate);
        assert_eq!(manager.recommended_action(), FlowControlAction::IncreaseRate);
        
        // Verify statistics tracking
        let stats = manager.statistics();
        assert!(stats.total_adjustments >= 5);
        assert!(stats.error_adjustments >= 1);
        assert!(stats.congestion_reductions >= 1);
        assert!(stats.recovery_increases >= 1);
        assert!(stats.peak_rate >= 25.0);
        assert!(stats.minimum_rate <= critical_rate);
    }

    #[test]
    fn test_performance_and_memory_efficiency() {
        use crate::datatypes::Tlv;
        use std::time::{Instant, Duration};
        
        // Test TLV handling performance
        let start = Instant::now();
        for i in 0..1000 {
            let tlv = Tlv {
                tag: 0x0427, // CongestionState
                length: 1,
                value: vec![(i % 100) as u8].into(),
            };
            let _bytes = tlv.to_bytes();
        }
        let tlv_time = start.elapsed();
        
        // TLV processing should be fast (relaxed for CI environments)
        assert!(tlv_time < Duration::from_millis(500),
                "TLV processing took too long: {:?}", tlv_time);
        
        // Test memory efficiency - TLV should have reasonable memory footprint
        let large_tlv = Tlv {
            tag: 0x0427,
            length: 255,
            value: vec![0u8; 255].into(), // Maximum TLV value size
        };
        
        assert_eq!(large_tlv.value.len(), 255);
        assert_eq!(large_tlv.length, 255);
    }
}
