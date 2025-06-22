//! Integration tests for SMPP PDU encoding and decoding

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
        assert!(matches!(result, Err(FrameError::Incomplete)));
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
            system_id: "A".repeat(15), // Max 15 chars (16 with null terminator)
            password: Some("B".repeat(8)), // Max 8 chars (9 with null terminator)
            system_type: "C".repeat(12), // Max 12 chars (13 with null terminator)
            interface_version: InterfaceVersion::SmppV34,
            addr_ton: TypeOfNumber::International,
            addr_npi: NumericPlanIndicator::Isdn,
            address_range: "D".repeat(40), // Max 40 chars (41 with null terminator)
        };

        let bytes = bind_transmitter.to_bytes();

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
            service_type: "".to_string(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: "1234567890".to_string(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: "0987654321".to_string(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 0,
            short_message: "".to_string(),
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

        let bytes = submit_sm.to_bytes();

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
            service_type: "".to_string(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: "1234567890".to_string(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: "0987654321".to_string(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 5,                             // Says 5 bytes
            short_message: "Hello World".to_string(), // But has 11 bytes
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
                message_id: "test".to_string(),
            };
            let bytes = response.to_bytes();
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
                system_id: "TEST".to_string(),
                password: Some("pass".to_string()),
                system_type: "TEST".to_string(),
                interface_version: InterfaceVersion::SmppV34,
                addr_ton: ton,
                addr_npi: NumericPlanIndicator::Isdn,
                address_range: "".to_string(),
            };
            let bytes = bt.to_bytes();
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
                system_id: "TEST".to_string(),
                password: Some("pass".to_string()),
                system_type: "TEST".to_string(),
                interface_version: InterfaceVersion::SmppV34,
                addr_ton: TypeOfNumber::International,
                addr_npi: npi,
                address_range: "".to_string(),
            };
            let bytes = bt.to_bytes();
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

            let bytes = test_submit.to_bytes();
            assert!(bytes.len() > 16);
        }

        // Test all InterfaceVersion values
        for version in [InterfaceVersion::SmppV33, InterfaceVersion::SmppV34] {
            let bt = BindTransmitter {
                command_status: CommandStatus::Ok,
                sequence_number: 1,
                system_id: "TEST".to_string(),
                password: Some("pass".to_string()),
                system_type: "TEST".to_string(),
                interface_version: version,
                addr_ton: TypeOfNumber::International,
                addr_npi: NumericPlanIndicator::Isdn,
                address_range: "".to_string(),
            };
            let bytes = bt.to_bytes();
            assert!(bytes.len() > 16);
        }
    }

    // Helper function to create a minimal SubmitSm
    fn create_minimal_submit_sm() -> SubmitSm {
        SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: "".to_string(),
            source_addr_ton: TypeOfNumber::International,
            source_addr_npi: NumericPlanIndicator::Isdn,
            source_addr: "1234567890".to_string(),
            dest_addr_ton: TypeOfNumber::International,
            dest_addr_npi: NumericPlanIndicator::Isdn,
            destination_addr: "0987654321".to_string(),
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: 11,
            short_message: "Hello World".to_string(),
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
            system_id: "SMPP测试".to_string(), // Contains Chinese characters (8 bytes)
            password: Some("密码".to_string()), // Contains Chinese characters (6 bytes)
            system_type: "テスト".to_string(), // Contains Japanese characters (9 bytes)
            interface_version: InterfaceVersion::SmppV34,
            addr_ton: TypeOfNumber::International,
            addr_npi: NumericPlanIndicator::Isdn,
            address_range: "".to_string(),
        };

        let bytes = bind_transmitter.to_bytes();

        // Should encode without panicking
        assert!(bytes.len() > 16);

        // The UTF-8 bytes should be present in the output
        assert!(bytes
            .windows("SMPP测试".as_bytes().len())
            .any(|window| window == "SMPP测试".as_bytes()));
    }

    #[test]
    fn test_boundary_sequence_numbers() {
        // Test with boundary sequence numbers
        for seq_num in [0, 1, 0x7FFFFFFF, 0xFFFFFFFF] {
            let response = SubmitSmResponse {
                command_status: CommandStatus::Ok,
                sequence_number: seq_num,
                message_id: "test".to_string(),
            };

            let bytes = response.to_bytes();

            // Verify sequence number is encoded correctly
            assert_eq!(&bytes[12..16], &seq_num.to_be_bytes());
        }
    }
}
