//! SMPP v3.4 Protocol Frame Implementation
//!
//! Provides a type representing an SMPP protocol frame as well as utilities for
//! parsing frames from a byte array. This module implements the PDU (Protocol Data Unit)
//! format as defined in SMPP v3.4 Specification Section 2.2.
//!
//! ## SMPP v3.4 PDU Structure (Section 2.2.1)
//!
//! All SMPP PDUs follow the same basic structure:
//! ```text
//! +----------------+----------------+----------------+----------------+
//! | command_length (4 octets)       | command_id (4 octets)           |
//! +----------------+----------------+----------------+----------------+
//! | command_status (4 octets)       | sequence_number (4 octets)      |
//! +----------------+----------------+----------------+----------------+
//! | PDU Body (variable length, 0-N octets)                            |
//! +-------------------------------------------------------------------+
//! ```
//!
//! The mandatory 16-octet header is followed by an optional body containing
//! PDU-specific mandatory and optional parameters.

use crate::datatypes::tags;
use tracing::warn;
use crate::datatypes::{
    AddressRange, BindReceiver, BindReceiverResponse, BindTransceiver, BindTransceiverResponse,
    BindTransmitter, BindTransmitterResponse, CommandId, CommandStatus, DataCoding, DeliverSm,
    DeliverSmResponse, DestinationAddr, EnquireLink, EnquireLinkResponse, EsmClass, GenericNack,
    InterfaceVersion, MessageId, NumericPlanIndicator, Outbind, Password, PriorityFlag,
    ScheduleDeliveryTime, ServiceType, ShortMessage, SourceAddr, SubmitSm, SubmitSmResponse,
    SystemId, SystemType, Tlv, TypeOfNumber, Unbind, UnbindResponse, ValidityPeriod,
};
use bytes::Buf;
use core::fmt;
use num_enum::TryFromPrimitiveError;
use std::convert::TryFrom;
use std::io::Cursor;
use std::mem::size_of;
use std::num::TryFromIntError;
use std::string::FromUtf8Error;

/// SMPP v3.4 Protocol Data Unit (PDU) Frame
///
/// Represents all supported SMPP PDU types as defined in Section 4 of the SMPP v3.4 specification.
/// Each variant corresponds to a specific command_id value and PDU structure.
#[derive(Clone, Debug)]
pub enum Frame {
    /// bind_receiver PDU (Section 4.1.1, Command ID: 0x00000001)
    BindReceiver(BindReceiver),
    /// bind_receiver_resp PDU (Section 4.1.2, Command ID: 0x80000001)
    BindReceiverResponse(BindReceiverResponse),
    /// bind_transceiver PDU (Section 4.2.5, Command ID: 0x00000009)
    BindTransceiver(BindTransceiver),
    /// bind_transceiver_resp PDU (Section 4.2.6, Command ID: 0x80000009)
    BindTransceiverResponse(BindTransceiverResponse),
    /// bind_transmitter PDU (Section 4.1.1, Command ID: 0x00000002)
    BindTransmitter(BindTransmitter),
    /// bind_transmitter_resp PDU (Section 4.1.2, Command ID: 0x80000002)
    BindTransmitterResponse(BindTransmitterResponse),
    /// deliver_sm PDU (Section 4.6.1, Command ID: 0x00000005)
    DeliverSm(Box<DeliverSm>),
    /// deliver_sm_resp PDU (Section 4.6.2, Command ID: 0x80000005)
    DeliverSmResponse(DeliverSmResponse),
    /// enquire_link PDU (Section 4.11.1, Command ID: 0x00000015)
    EnquireLink(EnquireLink),
    /// enquire_link_resp PDU (Section 4.11.2, Command ID: 0x80000015)
    EnquireLinkResponse(EnquireLinkResponse),
    /// generic_nack PDU (Section 4.3.1, Command ID: 0x80000000)
    GenericNack(GenericNack),
    /// outbind PDU (Section 4.1.4, Command ID: 0x0000000B)
    Outbind(Outbind),
    /// submit_sm PDU (Section 4.4.1, Command ID: 0x00000004)
    SubmitSm(Box<SubmitSm>),
    /// submit_sm_resp PDU (Section 4.4.2, Command ID: 0x80000004)
    SubmitSmResponse(SubmitSmResponse),
    /// unbind PDU (Section 4.2.1, Command ID: 0x00000006)
    Unbind(Unbind),
    /// unbind_resp PDU (Section 4.2.2, Command ID: 0x80000006)
    UnbindResponse(UnbindResponse),
}

#[derive(Debug)]
pub enum Error {
    /// Not enough data is available to parse a message
    Incomplete,

    /// Invalid message encoding
    Other(crate::Error),
}

impl Frame {
    /// Validates PDU header and checks if complete frame is available for parsing.
    ///
    /// Implements the frame checking logic per SMPP v3.4 Section 2.2.1. All SMPP PDUs
    /// must have a minimum 16-octet header containing command_length, command_id,
    /// command_status, and sequence_number fields.
    ///
    /// ## SMPP v3.4 Compliance
    /// - Validates command_length field is within acceptable bounds
    /// - Ensures complete PDU is available in the buffer before parsing
    /// - Follows Section 2.2.1 PDU format requirements
    ///
    /// Returns the command_length value if a complete PDU is available.
    #[tracing::instrument]
    pub fn check(src: &mut Cursor<&[u8]>) -> Result<usize, Error> {
        // Read command_length field (first 4 octets of PDU per Section 2.2.1)
        let command_length = peek_u32(src)? as usize;

        // Validate PDU structure per SMPP v3.4 Section 2.2.1:
        // All PDUs have the same 16-octet header structure:
        //  - command_length (4 octets)   - Total PDU length including this field
        //  - command_id (4 octets)       - PDU type identifier
        //  - command_status (4 octets)   - Error code (0 for requests)
        //  - sequence_number (4 octets)  - PDU sequence number
        // Minimum valid PDU is 16 octets (header only, e.g., enquire_link)
        (command_length <= src.remaining() && command_length >= 16)
            .then_some(command_length)
            .ok_or(Error::Incomplete)
    }
}

/// Parse the mandatory 16-octet SMPP header from all PDUs (Section 2.2.1)
///
/// Extracts the common header fields present in every SMPP PDU:
/// - command_length: Already validated by Frame::check()
/// - command_id: Identifies the PDU type (see Table 4-1 in specification)
/// - command_status: Error code for responses, must be 0 for requests (Section 5.1.3)
/// - sequence_number: Used to correlate requests with responses (Section 2.7.4)
///
/// ## SMPP v3.4 Reference
/// Per Section 2.2.1, all PDUs start with this identical 16-octet header structure.
#[tracing::instrument]
fn parse_header(src: &mut Cursor<&[u8]>) -> Result<(CommandId, CommandStatus, u32), Error> {
    let _command_length = get_u32(src)?; // Already validated in Frame::check()
    let command_id = CommandId::try_from(get_u32(src)?)?; // PDU type per Table 4-1
    let command_status = CommandStatus::try_from(get_u32(src)?)?; // Error code per Section 5.1.3
    let sequence_number = get_u32(src)?; // Sequence number per Section 2.7.4

    Ok((command_id, command_status, sequence_number))
}

/// Common fields shared by all bind PDU types per SMPP v3.4 Section 4.1
///
/// All bind operations (bind_transmitter, bind_receiver, bind_transceiver) share
/// the same body structure as defined in Table 4-1 of the specification.
struct BindFields {
    system_id: SystemId,        // System identifier (16 octets max per Table 4-1)
    password: Option<Password>, // Authentication password (9 octets max per Table 4-1)
    system_type: SystemType,    // System type identifier (13 octets max per Table 4-1)
    interface_version: InterfaceVersion, // SMPP version (1 octet, should be 0x34 for v3.4)
    addr_ton: TypeOfNumber,     // Type of Number for ESME address
    addr_npi: NumericPlanIndicator, // Numbering Plan Indicator for ESME address
    address_range: AddressRange, // ESME address range (41 octets max per Table 4-1)
}

/// Parse the common body fields for bind PDUs per SMPP v3.4 Section 4.1
///
/// Extracts the mandatory parameters present in all bind operations:
/// bind_transmitter (Section 4.1.1), bind_receiver (Section 4.1.1),
/// and bind_transceiver (Section 4.2.5).
#[tracing::instrument]
fn parse_bind_fields(src: &mut Cursor<&[u8]>) -> Result<BindFields, Error> {
    let system_id = get_cstring_field(src, 16, "system_id")?;
    let password = get_cstring_field(src, 9, "password")?;
    let system_type = get_cstring_field(src, 13, "system_type")?;
    let interface_version = InterfaceVersion::try_from(get_u8(src)?)?;
    let addr_ton = TypeOfNumber::try_from(get_u8(src)?)?;
    let addr_npi = NumericPlanIndicator::try_from(get_u8(src)?)?;
    let address_range = get_cstring_field(src, 41, "address_range")?;

    Ok(BindFields {
        system_id: SystemId::from_parsed_string(system_id)
            .map_err(|e| Error::Other(Box::new(e)))?,
        password: if password.is_empty() {
            None
        } else {
            Some(Password::from_parsed_string(password).map_err(|e| Error::Other(Box::new(e)))?)
        },
        system_type: SystemType::from_parsed_string(system_type)
            .map_err(|e| Error::Other(Box::new(e)))?,
        interface_version,
        addr_ton,
        addr_npi,
        address_range: AddressRange::from_parsed_string(address_range)
            .map_err(|e| Error::Other(Box::new(e)))?,
    })
}

/// Parse a BindTransmitter PDU
#[tracing::instrument]
fn parse_bind_transmitter(
    command_status: CommandStatus,
    sequence_number: u32,
    src: &mut Cursor<&[u8]>,
) -> Result<Frame, Error> {
    let fields = parse_bind_fields(src)?;

    let pdu = BindTransmitter {
        command_status,
        sequence_number,
        system_id: fields.system_id,
        password: fields.password,
        system_type: fields.system_type,
        interface_version: fields.interface_version,
        addr_ton: fields.addr_ton,
        addr_npi: fields.addr_npi,
        address_range: fields.address_range,
    };

    Ok(Frame::BindTransmitter(pdu))
}

/// Parse a BindReceiver PDU
#[tracing::instrument]
fn parse_bind_receiver(
    command_status: CommandStatus,
    sequence_number: u32,
    src: &mut Cursor<&[u8]>,
) -> Result<Frame, Error> {
    let fields = parse_bind_fields(src)?;

    let pdu = BindReceiver {
        command_status,
        sequence_number,
        system_id: fields.system_id,
        password: fields.password,
        system_type: fields.system_type,
        interface_version: fields.interface_version,
        addr_ton: fields.addr_ton,
        addr_npi: fields.addr_npi,
        address_range: fields.address_range,
    };

    Ok(Frame::BindReceiver(pdu))
}

/// Parse a BindTransceiver PDU
#[tracing::instrument]
fn parse_bind_transceiver(
    command_status: CommandStatus,
    sequence_number: u32,
    src: &mut Cursor<&[u8]>,
) -> Result<Frame, Error> {
    let fields = parse_bind_fields(src)?;

    let pdu = BindTransceiver {
        command_status,
        sequence_number,
        system_id: fields.system_id,
        password: fields.password,
        system_type: fields.system_type,
        interface_version: fields.interface_version,
        addr_ton: fields.addr_ton,
        addr_npi: fields.addr_npi,
        address_range: fields.address_range,
    };

    Ok(Frame::BindTransceiver(pdu))
}

/// TLV fields for SubmitSm PDU
struct SubmitSmTlvs {
    user_message_reference: Option<Tlv>,
    source_port: Option<Tlv>,
    source_addr_submit: Option<Tlv>,
    destination_port: Option<Tlv>,
    dest_addr_submit: Option<Tlv>,
    sar_msg_ref_num: Option<Tlv>,
    sar_total_segments: Option<Tlv>,
    sar_segment_seqnum: Option<Tlv>,
    more_messages_to_send: Option<Tlv>,
    payload_type: Option<Tlv>,
    message_payload: Option<Tlv>,
    privacy_indicator: Option<Tlv>,
    callback_num: Option<Tlv>,
    callback_num_pres_ind: Option<Tlv>,
    callback_num_atag: Option<Tlv>,
    source_subaddress: Option<Tlv>,
    dest_subaddress: Option<Tlv>,
    display_time: Option<Tlv>,
    sms_signal: Option<Tlv>,
    ms_validity: Option<Tlv>,
    ms_msg_wait_facilities: Option<Tlv>,
    number_of_messages: Option<Tlv>,
    alert_on_msg_delivery: Option<Tlv>,
    language_indicator: Option<Tlv>,
    its_reply_type: Option<Tlv>,
    its_session_info: Option<Tlv>,
    ussd_service_op: Option<Tlv>,
}

/// Parse TLV parameters for SubmitSm PDU
#[tracing::instrument]
fn parse_submit_sm_tlvs(
    src: &mut Cursor<&[u8]>,
    short_message: &ShortMessage,
) -> Result<SubmitSmTlvs, Error> {
    let mut user_message_reference = None;
    let mut source_port = None;
    let mut source_addr_submit = None;
    let mut destination_port = None;
    let mut dest_addr_submit = None;
    let mut sar_msg_ref_num = None;
    let mut sar_total_segments = None;
    let mut sar_segment_seqnum = None;
    let mut more_messages_to_send = None;
    let mut payload_type = None;
    let mut message_payload = None;
    let mut privacy_indicator = None;
    let mut callback_num = None;
    let mut callback_num_pres_ind = None;
    let mut callback_num_atag = None;
    let mut source_subaddress = None;
    let mut dest_subaddress = None;
    let mut display_time = None;
    let mut sms_signal = None;
    let mut ms_validity = None;
    let mut ms_msg_wait_facilities = None;
    let mut number_of_messages = None;
    let mut alert_on_msg_delivery = None;
    let mut language_indicator = None;
    let mut its_reply_type = None;
    let mut its_session_info = None;
    let mut ussd_service_op = None;

    while src.has_remaining() {
        let tlv = get_tlv(src)?;
        match tlv.tag {
            tags::USER_MESSAGE_REFERENCE => user_message_reference = Some(tlv),
            tags::SOURCE_PORT => source_port = Some(tlv),
            tags::SOURCE_ADDR_SUBMIT => source_addr_submit = Some(tlv),
            tags::DESTINATION_PORT => destination_port = Some(tlv),
            tags::DEST_ADDR_SUBMIT => dest_addr_submit = Some(tlv),
            tags::SAR_MSG_REF_NUM => sar_msg_ref_num = Some(tlv),
            tags::SAR_TOTAL_SEGMENTS => sar_total_segments = Some(tlv),
            tags::SAR_SEGMENT_SEQNUM => sar_segment_seqnum = Some(tlv),
            tags::MORE_MESSAGES_TO_SEND => more_messages_to_send = Some(tlv),
            tags::PAYLOAD_TYPE => payload_type = Some(tlv),
            tags::MESSAGE_PAYLOAD => {
                // Validate mutual exclusivity with short_message
                if !short_message.is_empty() {
                    return Err(Error::Other("Cannot use both short_message and message_payload - they are mutually exclusive".into()));
                }
                message_payload = Some(tlv);
            }
            tags::PRIVACY_INDICATOR => privacy_indicator = Some(tlv),
            tags::CALLBACK_NUM => callback_num = Some(tlv),
            tags::CALLBACK_NUM_PRES_IND => callback_num_pres_ind = Some(tlv),
            tags::CALLBACK_NUM_ATAG => callback_num_atag = Some(tlv),
            tags::SOURCE_SUBADDRESS => source_subaddress = Some(tlv),
            tags::DEST_SUBADDRESS => dest_subaddress = Some(tlv),
            tags::DISPLAY_TIME => display_time = Some(tlv),
            tags::SMS_SIGNAL => sms_signal = Some(tlv),
            tags::MS_VALIDITY => ms_validity = Some(tlv),
            tags::MS_MSG_WAIT_FACILITIES => ms_msg_wait_facilities = Some(tlv),
            tags::NUMBER_OF_MESSAGES => number_of_messages = Some(tlv),
            tags::ALERT_ON_MSG_DELIVERY => alert_on_msg_delivery = Some(tlv),
            tags::LANGUAGE_INDICATOR => language_indicator = Some(tlv),
            tags::ITS_REPLY_TYPE => its_reply_type = Some(tlv),
            tags::ITS_SESSION_INFO => its_session_info = Some(tlv),
            tags::USSD_SERVICE_OP => ussd_service_op = Some(tlv),
            _ => {
                // Unknown TLV - log warning but continue
                tracing::warn!("Unknown TLV tag: 0x{:04X}", tlv.tag);
            }
        }
    }

    Ok(SubmitSmTlvs {
        user_message_reference,
        source_port,
        source_addr_submit,
        destination_port,
        dest_addr_submit,
        sar_msg_ref_num,
        sar_total_segments,
        sar_segment_seqnum,
        more_messages_to_send,
        payload_type,
        message_payload,
        privacy_indicator,
        callback_num,
        callback_num_pres_ind,
        callback_num_atag,
        source_subaddress,
        dest_subaddress,
        display_time,
        sms_signal,
        ms_validity,
        ms_msg_wait_facilities,
        number_of_messages,
        alert_on_msg_delivery,
        language_indicator,
        its_reply_type,
        its_session_info,
        ussd_service_op,
    })
}

/// Parse a submit_sm PDU per SMPP v3.4 Section 4.4.1
///
/// The submit_sm operation is used by an ESME to submit a short message to the SMSC
/// for onward transmission to a specified short message entity (SME).
///
/// ## PDU Structure (Section 4.4.1)
/// Mandatory Parameters:
/// - service_type, source_addr_ton, source_addr_npi, source_addr
/// - dest_addr_ton, dest_addr_npi, destination_addr
/// - esm_class, protocol_id, priority_flag
/// - schedule_delivery_time, validity_period
/// - registered_delivery, replace_if_present_flag
/// - data_coding, sm_default_msg_id, sm_length, short_message
///
/// Optional Parameters (TLV format per Section 5.3):
/// - Various TLV parameters for enhanced messaging features
#[tracing::instrument]
fn parse_submit_sm(
    command_status: CommandStatus,
    sequence_number: u32,
    src: &mut Cursor<&[u8]>,
) -> Result<Frame, Error> {
    // Parse mandatory fields
    let service_type = ServiceType::from_parsed_string(get_cstring_field(src, 6, "service_type")?)
        .map_err(|e| Error::Other(format!("service_type field error: {e}").into()))?;

    let source_addr_ton = TypeOfNumber::try_from(get_u8(src)?)?;
    let source_addr_npi = NumericPlanIndicator::try_from(get_u8(src)?)?;
    let source_addr = SourceAddr::from_parsed_string(get_cstring_field(src, 21, "source_addr")?)
        .map_err(|e| Error::Other(format!("source_addr field error: {e}").into()))?;
    let dest_addr_ton = TypeOfNumber::try_from(get_u8(src)?)?;
    let dest_addr_npi = NumericPlanIndicator::try_from(get_u8(src)?)?;
    let destination_addr =
        DestinationAddr::from_parsed_string(get_cstring_field(src, 21, "destination_addr")?)
            .map_err(|e| Error::Other(format!("destination_addr field error: {e}").into()))?;

    let esm_class = get_u8(src)?;
    let protocol_id = get_u8(src)?;
    let priority_flag = PriorityFlag::try_from(get_u8(src)?)?;
    let schedule_delivery_time = ScheduleDeliveryTime::from_parsed_string(get_cstring_field(
        src,
        17,
        "schedule_delivery_time",
    )?)
    .map_err(|e| Error::Other(format!("schedule_delivery_time field error: {e}").into()))?;
    let validity_period =
        ValidityPeriod::from_parsed_string(get_cstring_field(src, 17, "validity_period")?)
            .map_err(|e| Error::Other(format!("validity_period field error: {e}").into()))?;
    let registered_delivery = get_u8(src)?;
    let replace_if_present_flag = get_u8(src)?;
    let data_coding = get_u8(src)?;
    let sm_default_msg_id = get_u8(src)?;
    let sm_length = get_u8(src)?;

    // Validate sm_length is within bounds
    if sm_length > 254 {
        return Err(Error::Other(
            format!("sm_length ({sm_length}) exceeds maximum of 254 bytes").into(),
        ));
    }

    // Ensure we have enough remaining bytes for the short message
    if src.remaining() < sm_length as usize {
        return Err(Error::Incomplete);
    }

    // Read short message based on sm_length
    let short_message = if sm_length > 0 {
        let message_bytes = src.copy_to_bytes(sm_length as usize);
        let message_string = String::from_utf8(message_bytes.into())
            .map_err(|e| Error::Other(format!("Invalid UTF-8 in short_message: {e}").into()))?;
        ShortMessage::from_parsed_string(message_string)
            .map_err(|e| Error::Other(format!("short_message field error: {e}").into()))?
    } else {
        ShortMessage::default()
    };

    // Parse optional TLV parameters
    let tlvs = parse_submit_sm_tlvs(src, &short_message)?;

    let pdu = SubmitSm {
        command_status,
        sequence_number,
        service_type,
        source_addr_ton,
        source_addr_npi,
        source_addr,
        dest_addr_ton,
        dest_addr_npi,
        destination_addr,
        esm_class: EsmClass::from(esm_class),
        protocol_id,
        priority_flag,
        schedule_delivery_time,
        validity_period,
        registered_delivery,
        replace_if_present_flag,
        data_coding: DataCoding::from(data_coding),
        sm_default_msg_id,
        sm_length,
        short_message,
        user_message_reference: tlvs.user_message_reference,
        source_port: tlvs.source_port,
        source_addr_submit: tlvs.source_addr_submit,
        destination_port: tlvs.destination_port,
        dest_addr_submit: tlvs.dest_addr_submit,
        sar_msg_ref_num: tlvs.sar_msg_ref_num,
        sar_total_segments: tlvs.sar_total_segments,
        sar_segment_seqnum: tlvs.sar_segment_seqnum,
        more_messages_to_send: tlvs.more_messages_to_send,
        payload_type: tlvs.payload_type,
        message_payload: tlvs.message_payload,
        privacy_indicator: tlvs.privacy_indicator,
        callback_num: tlvs.callback_num,
        callback_num_pres_ind: tlvs.callback_num_pres_ind,
        callback_num_atag: tlvs.callback_num_atag,
        source_subaddress: tlvs.source_subaddress,
        dest_subaddress: tlvs.dest_subaddress,
        display_time: tlvs.display_time,
        sms_signal: tlvs.sms_signal,
        ms_validity: tlvs.ms_validity,
        ms_msg_wait_facilities: tlvs.ms_msg_wait_facilities,
        number_of_messages: tlvs.number_of_messages,
        alert_on_msg_delivery: tlvs.alert_on_msg_delivery,
        language_indicator: tlvs.language_indicator,
        its_reply_type: tlvs.its_reply_type,
        its_session_info: tlvs.its_session_info,
        ussd_service_op: tlvs.ussd_service_op,
    };

    Ok(Frame::SubmitSm(Box::new(pdu)))
}

impl Frame {
    /// The message has already been validated with `check`.
    #[tracing::instrument]
    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Frame, Error> {
        // Parse common header
        let (command_id, command_status, sequence_number) = parse_header(src)?;

        // Based on the command_id, parse the body
        let command = match command_id {
            CommandId::BindTransmitter => {
                parse_bind_transmitter(command_status, sequence_number, src)?
            }
            CommandId::BindTransmitterResp => {
                let system_id = get_cstring_field(src, 16, "system_id")?;

                let sc_interface_version = match src.has_remaining() {
                    true => Some(get_tlv(src)?),
                    false => None,
                };

                let pdu = BindTransmitterResponse {
                    command_status,
                    sequence_number,
                    system_id: SystemId::from_parsed_string(system_id)
                        .map_err(|e| Error::Other(Box::new(e)))?,
                    sc_interface_version,
                };

                Frame::BindTransmitterResponse(pdu)
            }
            CommandId::BindReceiver => parse_bind_receiver(command_status, sequence_number, src)?,
            CommandId::BindReceiverResp => {
                let system_id = get_cstring_field(src, 16, "system_id")?;

                let sc_interface_version = match src.has_remaining() {
                    true => Some(get_tlv(src)?),
                    false => None,
                };

                let pdu = BindReceiverResponse {
                    command_status,
                    sequence_number,
                    system_id: SystemId::from_parsed_string(system_id)
                        .map_err(|e| Error::Other(Box::new(e)))?,
                    sc_interface_version,
                };

                Frame::BindReceiverResponse(pdu)
            }
            CommandId::EnquireLink => {
                let pdu = EnquireLink { sequence_number };
                Frame::EnquireLink(pdu)
            }
            CommandId::EnquireLinkResp => {
                let pdu = EnquireLinkResponse { sequence_number };
                Frame::EnquireLinkResponse(pdu)
            }
            CommandId::SubmitSmResp => {
                let message_id =
                    MessageId::from_parsed_string(get_cstring_field(src, 65, "message_id")?)
                        .map_err(|e| Error::Other(format!("message_id field error: {e}").into()))?;

                let pdu = SubmitSmResponse {
                    command_status,
                    sequence_number,
                    message_id,
                };

                Frame::SubmitSmResponse(pdu)
            }
            CommandId::SubmitSm => parse_submit_sm(command_status, sequence_number, src)?,
            CommandId::Unbind => {
                let pdu = Unbind {
                    command_status,
                    sequence_number,
                };
                Frame::Unbind(pdu)
            }
            CommandId::UnbindResp => {
                let pdu = UnbindResponse {
                    command_status,
                    sequence_number,
                };
                Frame::UnbindResponse(pdu)
            }
            CommandId::BindTransceiver => {
                parse_bind_transceiver(command_status, sequence_number, src)?
            }
            CommandId::BindTransceiverResp => {
                let system_id = get_cstring_field(src, 16, "system_id")?;

                let sc_interface_version = match src.has_remaining() {
                    true => Some(get_tlv(src)?),
                    false => None,
                };

                let pdu = BindTransceiverResponse {
                    command_status,
                    sequence_number,
                    system_id: SystemId::from_parsed_string(system_id)
                        .map_err(|e| Error::Other(Box::new(e)))?,
                    sc_interface_version,
                };

                Frame::BindTransceiverResponse(pdu)
            }
            CommandId::DeliverSm => {
                // Parse mandatory fields
                let service_type = get_cstring_field(src, 6, "service_type")?;
                let source_addr_ton = TypeOfNumber::try_from(get_u8(src)?)?;
                let source_addr_npi = NumericPlanIndicator::try_from(get_u8(src)?)?;
                let source_addr = get_cstring_field(src, 21, "source_addr")?;
                let dest_addr_ton = TypeOfNumber::try_from(get_u8(src)?)?;
                let dest_addr_npi = NumericPlanIndicator::try_from(get_u8(src)?)?;
                let destination_addr = get_cstring_field(src, 21, "destination_addr")?;
                let esm_class = get_u8(src)?;
                let protocol_id = get_u8(src)?;
                let priority_flag = get_u8(src)?;
                let schedule_delivery_time = get_cstring_field(src, 17, "schedule_delivery_time")?;
                let validity_period = get_cstring_field(src, 17, "validity_period")?;
                let registered_delivery = get_u8(src)?;
                let replace_if_present_flag = get_u8(src)?;
                let data_coding = get_u8(src)?;
                let sm_default_msg_id = get_u8(src)?;

                // Parse sm_length and short_message
                let sm_length = get_u8(src)?;

                // Validate sm_length is within bounds
                if sm_length > 254 {
                    return Err(Error::Other(
                        format!("sm_length ({sm_length}) exceeds maximum of 254 bytes").into(),
                    ));
                }

                // Read short_message based on sm_length
                let short_message = if sm_length > 0 {
                    let message_bytes = src.copy_to_bytes(sm_length as usize);
                    String::from_utf8(message_bytes.into()).map_err(|e| {
                        Error::Other(format!("Invalid UTF-8 in short_message: {e}").into())
                    })?
                } else {
                    String::new()
                };

                // Parse optional TLV parameters
                let mut user_message_reference = None;
                let mut source_port = None;
                let mut destination_port = None;
                let mut sar_msg_ref_num = None;
                let mut sar_total_segments = None;
                let mut sar_segment_seqnum = None;
                let mut user_data_header = None;
                let mut privacy_indicator = None;
                let mut callback_num = None;
                let mut source_subaddress = None;
                let mut dest_subaddress = None;
                let mut language_indicator = None;
                let mut its_session_info = None;
                let mut network_error_code = None;
                let mut message_payload = None;
                let mut delivery_failure_reason = None;
                let mut additional_status_info_text = None;
                let mut dpf_result = None;
                let mut set_dpf = None;
                let mut ms_availability_status = None;
                let mut receipted_message_id = None;
                let mut message_state = None;

                while src.has_remaining() {
                    let tlv = get_tlv(src)?;
                    match tlv.tag {
                        tags::USER_MESSAGE_REFERENCE => user_message_reference = Some(tlv),
                        tags::SOURCE_PORT => source_port = Some(tlv),
                        tags::DESTINATION_PORT => destination_port = Some(tlv),
                        tags::SAR_MSG_REF_NUM => sar_msg_ref_num = Some(tlv),
                        tags::SAR_TOTAL_SEGMENTS => sar_total_segments = Some(tlv),
                        tags::SAR_SEGMENT_SEQNUM => sar_segment_seqnum = Some(tlv),
                        tags::USER_DATA_HEADER => user_data_header = Some(tlv),
                        tags::PRIVACY_INDICATOR => privacy_indicator = Some(tlv),
                        tags::CALLBACK_NUM => callback_num = Some(tlv),
                        tags::SOURCE_SUBADDRESS => source_subaddress = Some(tlv),
                        tags::DEST_SUBADDRESS => dest_subaddress = Some(tlv),
                        tags::LANGUAGE_INDICATOR => language_indicator = Some(tlv),
                        tags::ITS_SESSION_INFO => its_session_info = Some(tlv),
                        tags::NETWORK_ERROR_CODE => network_error_code = Some(tlv),
                        tags::MESSAGE_PAYLOAD => message_payload = Some(tlv),
                        tags::DELIVERY_FAILURE_REASON => delivery_failure_reason = Some(tlv),
                        tags::ADDITIONAL_STATUS_INFO_TEXT => {
                            additional_status_info_text = Some(tlv)
                        }
                        tags::DPF_RESULT => dpf_result = Some(tlv),
                        tags::SET_DPF => set_dpf = Some(tlv),
                        tags::MS_AVAILABILITY_STATUS => ms_availability_status = Some(tlv),
                        tags::RECEIPTED_MESSAGE_ID => receipted_message_id = Some(tlv),
                        tags::MESSAGE_STATE => message_state = Some(tlv),
                        _ => {
                            // Unknown TLV, skip or handle as needed
                            warn!(tag = tlv.tag, "Unknown TLV tag in DeliverSm: 0x{:04x}", tlv.tag);
                        }
                    }
                }

                let pdu = DeliverSm {
                    command_status,
                    sequence_number,
                    service_type: ServiceType::from_parsed_string(service_type)
                        .map_err(|e| Error::Other(Box::new(e)))?,
                    source_addr_ton,
                    source_addr_npi,
                    source_addr: SourceAddr::from_parsed_string(source_addr)
                        .map_err(|e| Error::Other(Box::new(e)))?,
                    dest_addr_ton,
                    dest_addr_npi,
                    destination_addr: DestinationAddr::from_parsed_string(destination_addr)
                        .map_err(|e| Error::Other(Box::new(e)))?,
                    esm_class: EsmClass::from(esm_class),
                    protocol_id,
                    priority_flag,
                    schedule_delivery_time: ScheduleDeliveryTime::from_parsed_string(
                        schedule_delivery_time,
                    )
                    .map_err(|e| Error::Other(Box::new(e)))?,
                    validity_period: ValidityPeriod::from_parsed_string(validity_period)
                        .map_err(|e| Error::Other(Box::new(e)))?,
                    registered_delivery,
                    replace_if_present_flag,
                    data_coding: DataCoding::from(data_coding),
                    sm_default_msg_id,
                    sm_length,
                    short_message: ShortMessage::from_parsed_string(short_message)
                        .map_err(|e| Error::Other(Box::new(e)))?,
                    user_message_reference,
                    source_port,
                    destination_port,
                    sar_msg_ref_num,
                    sar_total_segments,
                    sar_segment_seqnum,
                    user_data_header,
                    privacy_indicator,
                    callback_num,
                    source_subaddress,
                    dest_subaddress,
                    language_indicator,
                    its_session_info,
                    network_error_code,
                    message_payload,
                    delivery_failure_reason,
                    additional_status_info_text,
                    dpf_result,
                    set_dpf,
                    ms_availability_status,
                    receipted_message_id,
                    message_state,
                };

                Frame::DeliverSm(Box::new(pdu))
            }
            CommandId::DeliverSmResp => {
                let message_id = get_cstring_field(src, 65, "message_id")?;

                let pdu = DeliverSmResponse {
                    command_status,
                    sequence_number,
                    message_id: MessageId::from_parsed_string(message_id)
                        .map_err(|e| Error::Other(Box::new(e)))?,
                };

                Frame::DeliverSmResponse(pdu)
            }
            CommandId::Outbind => {
                let system_id = get_cstring_field(src, 16, "system_id")?;
                let password = get_cstring_field(src, 9, "password")?;

                let pdu = Outbind {
                    sequence_number,
                    system_id: SystemId::from_parsed_string(system_id)
                        .map_err(|e| Error::Other(Box::new(e)))?,
                    password: if password.is_empty() {
                        None
                    } else {
                        Some(
                            Password::from_parsed_string(password)
                                .map_err(|e| Error::Other(Box::new(e)))?,
                        )
                    },
                };

                Frame::Outbind(pdu)
            }
            CommandId::GenericNack => {
                // GenericNack has no body, only the standard header
                let pdu = GenericNack {
                    command_status,
                    sequence_number,
                };

                Frame::GenericNack(pdu)
            }

            _ => {
                warn!(command_id = ?command_id, value = command_id.clone() as u32, "Unimplemented command ID: {command_id:?} (0x{:08x})", command_id.clone() as u32);
                todo!("Implement the parse function for all the other PDUs")
            }
        };

        Ok(command)
    }

    // /// Converts the frame to an "unexpected frame" error
    // pub(crate) fn to_error(&self) -> crate::Error {
    //     format!("unexpected frame: {}", self).into()
    // }
}

/// Peek a u8 from the buffer
#[cfg(test)]
#[tracing::instrument]
fn peek_u8(src: &mut Cursor<&[u8]>) -> Result<u8, Error> {
    src.has_remaining()
        .then(|| {
            let starting_position = src.position();
            let val = src.get_u8();
            src.set_position(starting_position);
            val
        })
        .ok_or(Error::Incomplete)
}

/// Peek a u32 from the buffer
#[tracing::instrument]
fn peek_u32(src: &mut Cursor<&[u8]>) -> Result<u32, Error> {
    (src.remaining() >= size_of::<u32>())
        .then(|| {
            let starting_position = src.position();
            let val = src.get_u32();
            src.set_position(starting_position);
            val
        })
        .ok_or(Error::Incomplete)
}

/// Get a u8 from the buffer
#[tracing::instrument]
fn get_u8(src: &mut Cursor<&[u8]>) -> Result<u8, Error> {
    src.has_remaining()
        .then(|| src.get_u8())
        .ok_or(Error::Incomplete)
}

/// Get a u16 from the buffer
#[tracing::instrument]
fn get_u16(src: &mut Cursor<&[u8]>) -> Result<u16, Error> {
    (src.remaining() >= size_of::<u16>())
        .then(|| src.get_u16())
        .ok_or(Error::Incomplete)
}

/// Get a u32 from the buffer
#[tracing::instrument]
fn get_u32(src: &mut Cursor<&[u8]>) -> Result<u32, Error> {
    (src.remaining() >= size_of::<u32>())
        .then(|| src.get_u32())
        .ok_or(Error::Incomplete)
}

#[tracing::instrument]
fn get_cstring_field(
    src: &mut Cursor<&[u8]>,
    max_length: usize,
    field_name: &str,
) -> Result<String, Error> {
    if !src.has_remaining() {
        return Err(Error::Other(
            format!("No data available for field {field_name}").into(),
        ));
    }

    let _start_pos = src.position();
    let available_bytes = src.remaining().min(max_length);

    // Look for null terminator within field bounds
    let mut terminator_pos = None;
    let current_chunk = src.chunk();
    for i in 0..available_bytes {
        if i < current_chunk.len() && current_chunk[i] == 0 {
            terminator_pos = Some(i);
            break;
        }
    }

    let string_length = match terminator_pos {
        Some(pos) => pos,
        None => {
            // If no null terminator found within max_length, check if we hit the field boundary
            if available_bytes == max_length {
                // Field uses full width without null terminator - handle gracefully but log warning
                tracing::warn!(
                    "Field {} missing null terminator, using full field length",
                    field_name
                );
                max_length.saturating_sub(1) // Reserve space for implied null terminator
            } else {
                return Err(Error::Other(
                    format!(
                        "Missing null terminator in field {field_name} (available: {available_bytes}, max: {max_length})"
                    )
                    .into(),
                ));
            }
        }
    };

    // Extract string content only (without null terminator)
    let string_bytes = src.copy_to_bytes(string_length);

    // Skip null terminator if present
    if terminator_pos.is_some() && src.has_remaining() {
        src.advance(1);
    }

    // Validate UTF-8 and convert
    match String::from_utf8(string_bytes.into()) {
        Ok(s) => Ok(s),
        Err(e) => Err(Error::Other(
            format!("Invalid UTF-8 in field {field_name}: {e}").into(),
        )),
    }
}

// Keep the old function for backward compatibility during transition

#[tracing::instrument]
fn get_tlv(src: &mut Cursor<&[u8]>) -> Result<Tlv, Error> {
    if !&src.has_remaining() {
        return Err(Error::Incomplete);
    }

    let tag = get_u16(src)?;
    let length = get_u16(src)?;
    let value = src.copy_to_bytes(length as usize);

    let tlv = Tlv { tag, length, value };

    Ok(tlv)
}

/// Advance the buffer by n bytes. If there are not enough bytes remaining,
/// return an error indicating that the data is incomplete.
#[cfg(test)]
#[tracing::instrument]
fn skip(src: &mut Cursor<&[u8]>, n: usize) -> Result<(), Error> {
    (src.remaining() >= n)
        .then(|| src.advance(n))
        .ok_or(Error::Incomplete)
}

impl fmt::Display for Frame {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        // TODO: we can probably do a lot better here...
        match self {
            Frame::BindTransmitter(msg) => {
                write!(fmt, "Bind Transmitter {:?}", msg.command_status)
            }
            Frame::BindTransmitterResponse(msg) => {
                write!(fmt, "Bind Transmitter Response {:?}", msg.command_status)
            }
            Frame::EnquireLink(msg) => {
                write!(fmt, "Enquire Link {:?}", msg.sequence_number)
            }
            Frame::EnquireLinkResponse(msg) => {
                write!(fmt, "Enquire Link Response {:?}", msg.sequence_number)
            }
            Frame::SubmitSm(msg) => {
                write!(fmt, "Submit SM {:?}", msg.command_status)
            }
            Frame::SubmitSmResponse(msg) => {
                write!(fmt, "Submit SM Response {:?}", msg.command_status)
            }
            Frame::Unbind(msg) => {
                write!(fmt, "Unbind {:?}", msg.command_status)
            }
            Frame::UnbindResponse(msg) => {
                write!(fmt, "Unbind Response {:?}", msg.command_status)
            }
            Frame::BindReceiver(msg) => {
                write!(fmt, "Bind Receiver {:?}", msg.command_status)
            }
            Frame::BindReceiverResponse(msg) => {
                write!(fmt, "Bind Receiver Response {:?}", msg.command_status)
            }
            Frame::BindTransceiver(msg) => {
                write!(fmt, "Bind Transceiver {:?}", msg.command_status)
            }
            Frame::BindTransceiverResponse(msg) => {
                write!(fmt, "Bind Transceiver Response {:?}", msg.command_status)
            }
            Frame::DeliverSm(msg) => {
                write!(fmt, "Deliver SM {:?}", msg.command_status)
            }
            Frame::DeliverSmResponse(msg) => {
                write!(fmt, "Deliver SM Response {:?}", msg.command_status)
            }
            Frame::Outbind(msg) => {
                write!(fmt, "Outbind {:?}", msg.sequence_number)
            }
            Frame::GenericNack(msg) => {
                write!(
                    fmt,
                    "Generic NACK {:?} (seq: {})",
                    msg.command_status, msg.sequence_number
                )
            }
        }
    }
}

impl From<String> for Error {
    fn from(src: String) -> Error {
        Error::Other(src.into())
    }
}

impl From<&str> for Error {
    fn from(src: &str) -> Error {
        src.to_string().into()
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_src: FromUtf8Error) -> Error {
        "protocol error; invalid frame format".into()
    }
}

impl From<TryFromIntError> for Error {
    fn from(_src: TryFromIntError) -> Error {
        "protocol error; invalid frame format".into()
    }
}

impl From<TryFromPrimitiveError<CommandId>> for Error {
    fn from(_src: TryFromPrimitiveError<CommandId>) -> Error {
        "protocol error; invalid command identifier in frame".into()
    }
}

impl From<TryFromPrimitiveError<CommandStatus>> for Error {
    fn from(_src: TryFromPrimitiveError<CommandStatus>) -> Error {
        "protocol error; invalid command status in frame".into()
    }
}

impl From<TryFromPrimitiveError<InterfaceVersion>> for Error {
    fn from(_src: TryFromPrimitiveError<InterfaceVersion>) -> Error {
        "protocol error; invalid interface version in frame".into()
    }
}

impl From<TryFromPrimitiveError<NumericPlanIndicator>> for Error {
    fn from(_src: TryFromPrimitiveError<NumericPlanIndicator>) -> Error {
        "protocol error; invalid numeric plan indicator in frame".into()
    }
}

impl From<TryFromPrimitiveError<TypeOfNumber>> for Error {
    fn from(_src: TryFromPrimitiveError<TypeOfNumber>) -> Error {
        "protocol error; invalid type of number in frame".into()
    }
}

impl From<TryFromPrimitiveError<PriorityFlag>> for Error {
    fn from(_src: TryFromPrimitiveError<PriorityFlag>) -> Error {
        "protocol error; invalid priority flag in frame".into()
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Incomplete => "stream ended early".fmt(fmt),
            Error::Other(err) => err.fmt(fmt),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use std::io::Cursor;

    #[test]
    fn peek_u8_test() {
        let data: Vec<u8> = vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        let mut buff = Cursor::new(data.as_slice());

        // Before peeking, the remaining bytes should be the same as the total number of elements
        assert_eq!(buff.remaining(), data.len());

        let result = peek_u8(&mut buff);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10u8);

        // Ensure that we are peeking ant not getting. (cursor position should not have moved)
        assert_eq!(buff.remaining(), data.len());
    }

    #[test]
    fn get_u8_test() {
        let data: Vec<u8> = vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        let mut buff = Cursor::new(data.as_slice());

        let result = get_u8(&mut buff);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10u8);

        // Ensure that the cursor has advanced
        assert_eq!(buff.remaining(), data.len() - 1);
    }

    #[test]
    fn peek_u32_test() {
        let data: Vec<u8> = vec![0x1, 0xF, 0xF, 0xF, 6, 5, 4, 3, 2, 1];
        let mut buff = Cursor::new(data.as_slice());

        let result = peek_u32(&mut buff);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            u32::from_be_bytes(data[0..4].try_into().unwrap())
        );

        // Ensure that we are peeking and not getting
        assert_eq!(buff.remaining(), data.len());
    }

    #[test]
    fn get_u32_test() {
        let data: Vec<u8> = vec![0x1, 0xF, 0xF, 0xF, 6, 5, 4, 3, 2, 1];
        let mut buff = Cursor::new(data.as_slice());

        let result = get_u32(&mut buff);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            u32::from_be_bytes(data[0..4].try_into().unwrap())
        );

        // Ensure that the cursor has advanced 4 bytes
        assert_eq!(buff.remaining(), data.len() - 4);
    }

    #[test]
    fn get_u16_test() {
        let data: Vec<u8> = vec![0x1, 0xF, 0xF, 0xF, 6, 5, 4, 3, 2, 1];
        let mut buff = Cursor::new(data.as_slice());

        let result = get_u16(&mut buff);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            u16::from_be_bytes(data[0..2].try_into().unwrap())
        );

        // Ensure that the cursor has advanced 4 bytes
        assert_eq!(buff.remaining(), data.len() - 2);
    }

    #[test]
    fn skip_test() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![0x1, 0xF, 0xF, 0xF, 6, 5, 4, 3, 2, 1];
        let mut buff = Cursor::new(data.as_slice());

        let result = skip(&mut buff, 4);
        assert!(result.is_ok());

        let result = get_u8(&mut buff);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 6u8);

        let result = skip(&mut buff, 2);
        assert!(result.is_ok());

        let result = get_u8(&mut buff);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3u8);

        // Ensure that the cursor has advanced 4 + 1 + 2 + 1 = 8 positions
        assert_eq!(buff.remaining(), data.len() - 8);
    }

    #[test]
    fn get_cstring_field_compatibility_test() {
        use std::io::Cursor;

        let data = "This is the first part\0This is the second.\0".as_bytes();
        let mut buff = Cursor::new(data);

        let result = get_cstring_field(&mut buff, 23, "test_field");
        assert!(result.is_ok());

        let result = result.unwrap();

        assert_eq!(result.len(), 22);
        assert_eq!("This is the first part".to_string(), result);

        // Ensure that the cursor has advanced 23 bytes (22 chars + null terminator)
        assert_eq!(buff.remaining(), data.len() - 23);

        let result = get_cstring_field(&mut buff, 256, "test_field");
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!("This is the second.".to_string(), result);

        let data = "This is the first part\0This is the second.\0".as_bytes();
        let mut buff = Cursor::new(data);

        let result = get_cstring_field(&mut buff, 4, "test_field");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3); // "Thi" - truncated at 4 bytes but excluding null terminator
    }

    #[test]
    fn check_test() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x2F, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x53, 0x4D, 0x50, 0x50, 0x33, 0x54, 0x45, 0x53, 0x54, 0x00, 0x73, 0x65,
            0x63, 0x72, 0x65, 0x74, 0x30, 0x38, 0x00, 0x53, 0x55, 0x42, 0x4D, 0x49, 0x54, 0x31,
            0x00, 0x00, 0x01, 0x01, 0x00,
        ];

        let data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::check(&mut buff);
        assert!(result.is_ok());

        // Invalid length: (0x3F when it should be 0x2F)
        let data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x53, 0x4D, 0x50, 0x50, 0x33, 0x54, 0x45, 0x53, 0x54, 0x00, 0x73, 0x65,
            0x63, 0x72, 0x65, 0x74, 0x30, 0x38, 0x00, 0x53, 0x55, 0x42, 0x4D, 0x49, 0x54, 0x31,
            0x00, 0x00, 0x01, 0x01, 0x00,
        ];

        let data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::check(&mut buff);
        assert!(result.is_err());
    }

    #[test]
    fn parse_bind_transmitter_test() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x2F, // command_length
            0x00, 0x00, 0x00, 0x02, // command_id
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body:
            0x53, 0x4D, 0x50, 0x50, 0x33, 0x54, 0x45, 0x53, 0x54, 0x00, // system_id
            0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x30, 0x38, 0x00, // password
            0x53, 0x55, 0x42, 0x4D, 0x49, 0x54, 0x31, 0x00, // system_type
            0x34, // interface_version
            0x01, // addr_ton
            0x01, // addr_npi
            0x00, // address_range
        ];

        let data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::parse(&mut buff);

        assert!(result.is_ok());

        let frame = result.unwrap();
        if let Frame::BindTransmitter(bt) = frame {
            assert_eq!(bt.command_status, CommandStatus::Ok);
            assert_eq!(&bt.system_id, "SMPP3TEST");
            assert_eq!(
                bt.password.as_ref().map(|p| p.as_str().unwrap()),
                Some("secret08")
            );
            assert_eq!(&bt.system_type, "SUBMIT1");
            assert_eq!(bt.interface_version, InterfaceVersion::SmppV34);
            assert_eq!(bt.addr_ton, TypeOfNumber::International);
            assert_eq!(bt.addr_npi, NumericPlanIndicator::Isdn);
            assert_eq!(&bt.address_range, "");
        } else {
            panic!("Unexpected frame variant");
        }
    }

    #[test]
    fn parse_bind_transmitter_response_test() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x1a, // command_length (26 bytes total)
            0x80, 0x00, 0x00, 0x02, // command_id (bind_transmitter_resp)
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body:
            0x53, 0x4D, 0x50, 0x50, 0x33, 0x54, 0x45, 0x53, 0x54,
            0x00, // system_id "SMPP3TEST\0"
                  // No TLV data - that's it
        ];

        let data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::parse(&mut buff);

        assert!(result.is_ok());

        let frame = result.unwrap();
        if let Frame::BindTransmitterResponse(btr) = frame {
            assert_eq!(btr.command_status, CommandStatus::Ok);
            assert_eq!(btr.sequence_number, 1);
            assert_eq!(&btr.system_id, "SMPP3TEST");
            assert!(btr.sc_interface_version.is_none());
        } else {
            panic!("Unexpected frame variant");
        }
    }

    #[test]
    fn parse_bind_transmitter_response_with_tlv_test() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x21, // command_length
            0x80, 0x00, 0x00, 0x02, // command_id (bind_transmitter_resp)
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body:
            0x53, 0x4D, 0x50, 0x50, 0x33, 0x54, 0x45, 0x53, 0x54, 0x00, // system_id
            // TLV:
            0x00, 0x10, // tag (sc_interface_version)
            0x00, 0x01, // length
            0x34, // value (interface version 3.4)
        ];

        let data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::parse(&mut buff);

        assert!(result.is_ok());

        let frame = result.unwrap();
        if let Frame::BindTransmitterResponse(btr) = frame {
            assert_eq!(btr.command_status, CommandStatus::Ok);
            assert_eq!(btr.sequence_number, 1);
            assert_eq!(&btr.system_id, "SMPP3TEST");
            assert!(btr.sc_interface_version.is_some());
            let tlv = btr.sc_interface_version.unwrap();
            assert_eq!(tlv.tag, 0x0010);
            assert_eq!(tlv.length, 1);
            assert_eq!(tlv.value.as_ref(), &[0x34]);
        } else {
            panic!("Unexpected frame variant");
        }
    }

    #[test]
    fn parse_enquire_link_test() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x10, // command_length
            0x00, 0x00, 0x00, 0x15, // command_id (enquire_link)
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00,
            0x01, // sequence_number
                  // No body for enquire_link
        ];

        let data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::parse(&mut buff);

        assert!(result.is_ok());

        let frame = result.unwrap();
        if let Frame::EnquireLink(el) = frame {
            assert_eq!(el.sequence_number, 1);
        } else {
            panic!("Unexpected frame variant");
        }
    }

    #[test]
    fn parse_enquire_link_response_test() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x10, // command_length
            0x80, 0x00, 0x00, 0x15, // command_id (enquire_link_resp)
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00,
            0x01, // sequence_number
                  // No body for enquire_link_resp
        ];

        let data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::parse(&mut buff);

        assert!(result.is_ok());

        let frame = result.unwrap();
        if let Frame::EnquireLinkResponse(elr) = frame {
            assert_eq!(elr.sequence_number, 1);
        } else {
            panic!("Unexpected frame variant");
        }
    }

    #[test]
    fn parse_submit_sm_response_test() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x17, // command_length
            0x80, 0x00, 0x00, 0x04, // command_id (submit_sm_resp)
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body:
            0x6D, 0x73, 0x67, 0x5F, 0x69, 0x64, 0x00, // message_id "msg_id\0"
        ];

        let data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::parse(&mut buff);

        assert!(result.is_ok());

        let frame = result.unwrap();
        if let Frame::SubmitSmResponse(ssr) = frame {
            assert_eq!(ssr.command_status, CommandStatus::Ok);
            assert_eq!(ssr.sequence_number, 1);
            assert_eq!(&ssr.message_id, "msg_id");
        } else {
            panic!("Unexpected frame variant");
        }
    }

    #[test]
    fn parse_error_invalid_command_id() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x10, // command_length
            0x00, 0x00, 0xFF, 0xFF, // invalid command_id
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
        ];

        let data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::parse(&mut buff);

        assert!(result.is_err());
    }

    #[test]
    fn parse_error_invalid_command_status() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x10, // command_length
            0x00, 0x00, 0x00, 0x15, // command_id (enquire_link)
            0xFF, 0xFF, 0xFF, 0xFF, // invalid command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
        ];

        let data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::parse(&mut buff);

        assert!(result.is_err());
    }

    #[test]
    fn parse_error_incomplete_header() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x10, // command_length
            0x00, 0x00, 0x00, 0x15, // command_id
            0x00, 0x00, // incomplete header
        ];

        let data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::parse(&mut buff);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Incomplete => (),
            _ => panic!("Expected Incomplete error"),
        }
    }

    #[test]
    fn test_cstring_field_parsing() {
        use std::io::Cursor;

        // Test normal null-terminated string
        let data = b"TEST\0";
        let mut cursor = Cursor::new(&data[..]);
        let result = get_cstring_field(&mut cursor, 16, "test_field").unwrap();
        assert_eq!(result, "TEST");
        assert_eq!(cursor.position(), 5); // Should advance past null terminator

        // Test string at max length with null terminator
        let data = b"ABCDEFGHIJKLMNO\0"; // 15 chars + null = 16 total
        let mut cursor = Cursor::new(&data[..]);
        let result = get_cstring_field(&mut cursor, 16, "test_field").unwrap();
        assert_eq!(result, "ABCDEFGHIJKLMNO");

        // Test empty string
        let data = b"\0";
        let mut cursor = Cursor::new(&data[..]);
        let result = get_cstring_field(&mut cursor, 16, "test_field").unwrap();
        assert_eq!(result, "");

        // Test UTF-8 validation
        let data = b"Caf\xc3\xa9\0"; // "Café" in UTF-8
        let mut cursor = Cursor::new(&data[..]);
        let result = get_cstring_field(&mut cursor, 16, "test_field").unwrap();
        assert_eq!(result, "Café");
    }

    #[test]
    fn test_cstring_field_error_cases() {
        use std::io::Cursor;

        // Test missing null terminator within field boundary
        let data = b"TOOLONGWITHOUTTRUNCATION";
        let mut cursor = Cursor::new(&data[..]);
        let result = get_cstring_field(&mut cursor, 5, "test_field");
        assert!(result.is_ok()); // Should handle gracefully with warning

        // Test invalid UTF-8
        let data = b"\xff\xfe\0";
        let mut cursor = Cursor::new(&data[..]);
        let result = get_cstring_field(&mut cursor, 16, "test_field");
        assert!(result.is_err());

        // Test insufficient data
        let data = b"";
        let mut cursor = Cursor::new(&data[..]);
        let result = get_cstring_field(&mut cursor, 16, "test_field");
        assert!(result.is_err());
    }

    #[test]
    fn test_string_parsing_no_null_terminators() {
        use std::io::Cursor;

        // Test data with various string fields
        let data: Vec<u8> = vec![
            // Header
            0x00, 0x00, 0x00, 0x2F, // command_length
            0x00, 0x00, 0x00, 0x02, // command_id
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body
            b'T', b'E', b'S', b'T', 0x00, // system_id: "TEST\0"
            b'P', b'A', b'S', b'S', 0x00, // password: "PASS\0"
            b'T', b'Y', b'P', b'E', 0x00, // system_type: "TYPE\0"
            0x34, // interface_version
            0x01, // addr_ton
            0x01, // addr_npi
            0x00, // address_range: empty
        ];

        let mut cursor = Cursor::new(data.as_slice());
        let result = Frame::parse(&mut cursor).unwrap();

        if let Frame::BindTransmitter(bt) = result {
            // Fixed arrays should parse correctly
            assert_eq!(bt.system_id, SystemId::from("TEST"));
            assert_eq!(bt.password, Some(Password::from("PASS")));
            assert_eq!(bt.system_type, SystemType::from("TYPE"));
            assert_eq!(bt.address_range, AddressRange::from(""));

            // Verify no null bytes in string content
            assert!(!bt.system_id.as_str().unwrap().contains('\0'));
            assert!(!bt
                .password
                .as_ref()
                .unwrap()
                .as_str()
                .unwrap()
                .contains('\0'));
            assert!(!bt.system_type.as_str().unwrap().contains('\0'));
            assert!(!bt.address_range.as_str().unwrap().contains('\0'));
        } else {
            panic!("Expected BindTransmitter frame");
        }
    }

    #[test]
    fn test_field_length_boundaries() {
        use std::io::Cursor;

        // Test with maximum allowed field lengths per SMPP spec
        let system_id_max = "A".repeat(15); // 15 chars + null terminator = 16 total
        let password_max = "B".repeat(8); // 8 chars + null terminator = 9 total
        let system_type_max = "C".repeat(12); // 12 chars + null terminator = 13 total
        let address_range_max = "D".repeat(40); // 40 chars + null terminator = 41 total

        let mut data = Vec::new();
        // Header
        data.extend_from_slice(&0x00000000u32.to_be_bytes()); // command_length (will be updated)
        data.extend_from_slice(&0x00000002u32.to_be_bytes()); // command_id
        data.extend_from_slice(&0x00000000u32.to_be_bytes()); // command_status
        data.extend_from_slice(&0x00000001u32.to_be_bytes()); // sequence_number

        // Body with max length fields
        data.extend_from_slice(system_id_max.as_bytes());
        data.push(0); // null terminator
        data.extend_from_slice(password_max.as_bytes());
        data.push(0); // null terminator
        data.extend_from_slice(system_type_max.as_bytes());
        data.push(0); // null terminator
        data.push(0x34); // interface_version
        data.push(0x01); // addr_ton
        data.push(0x01); // addr_npi
        data.extend_from_slice(address_range_max.as_bytes());
        data.push(0); // null terminator

        // Update command_length
        let length = data.len() as u32;
        data[0..4].copy_from_slice(&length.to_be_bytes());

        let mut cursor = Cursor::new(data.as_slice());
        let result = Frame::parse(&mut cursor);

        assert!(result.is_ok());

        if let Frame::BindTransmitter(bt) = result.unwrap() {
            assert_eq!(bt.system_id, SystemId::from(system_id_max.as_str()));
            assert_eq!(bt.password, Some(Password::from(password_max.as_str())));
            assert_eq!(bt.system_type, SystemType::from(system_type_max.as_str()));
            assert_eq!(
                bt.address_range,
                AddressRange::from(address_range_max.as_str())
            );
        }
    }

    #[test]
    fn parse_submit_sm_basic_test() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x3B, // command_length (59 bytes)
            0x00, 0x00, 0x00, 0x04, // command_id (submit_sm)
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body:
            0x00, // service_type (empty)
            0x01, // source_addr_ton (International)
            0x01, // source_addr_npi (ISDN)
            b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', 0x00, // source_addr
            0x01, // dest_addr_ton (International)
            0x01, // dest_addr_npi (ISDN)
            b'0', b'9', b'8', b'7', b'6', b'5', b'4', b'3', b'2', b'1',
            0x00, // destination_addr
            0x00, // esm_class
            0x00, // protocol_id
            0x00, // priority_flag
            0x00, // schedule_delivery_time (empty)
            0x00, // validity_period (empty)
            0x00, // registered_delivery
            0x00, // replace_if_present_flag
            0x00, // data_coding
            0x00, // sm_default_msg_id
            0x0B, // sm_length (11 bytes)
            b'H', b'e', b'l', b'l', b'o', b' ', b'W', b'o', b'r', b'l', b'd', // short_message
        ];

        let mut cursor = Cursor::new(data.as_slice());
        let result = Frame::parse(&mut cursor);

        assert!(result.is_ok());

        if let Frame::SubmitSm(submit_sm) = result.unwrap() {
            assert_eq!(submit_sm.command_status, CommandStatus::Ok);
            assert_eq!(submit_sm.sequence_number, 1);
            assert_eq!(submit_sm.service_type, "");
            assert_eq!(submit_sm.source_addr_ton, TypeOfNumber::International);
            assert_eq!(submit_sm.source_addr_npi, NumericPlanIndicator::Isdn);
            assert_eq!(submit_sm.source_addr, "1234567890");
            assert_eq!(submit_sm.dest_addr_ton, TypeOfNumber::International);
            assert_eq!(submit_sm.dest_addr_npi, NumericPlanIndicator::Isdn);
            assert_eq!(submit_sm.destination_addr, "0987654321");
            assert_eq!(submit_sm.esm_class, EsmClass::default());
            assert_eq!(submit_sm.protocol_id, 0);
            assert_eq!(submit_sm.priority_flag, PriorityFlag::Level0);
            assert_eq!(submit_sm.schedule_delivery_time, "");
            assert_eq!(submit_sm.validity_period, "");
            assert_eq!(submit_sm.registered_delivery, 0);
            assert_eq!(submit_sm.replace_if_present_flag, 0);
            assert_eq!(submit_sm.data_coding, DataCoding::default());
            assert_eq!(submit_sm.sm_default_msg_id, 0);
            assert_eq!(submit_sm.sm_length, 11);
            assert_eq!(submit_sm.short_message.as_str().unwrap(), "Hello World");
            assert!(submit_sm.user_message_reference.is_none());
            assert!(submit_sm.message_payload.is_none());
        } else {
            panic!("Expected SubmitSm frame");
        }
    }

    #[test]
    fn parse_submit_sm_with_tlv_test() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x45, // command_length (69 bytes)
            0x00, 0x00, 0x00, 0x04, // command_id (submit_sm)
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body:
            0x00, // service_type (empty)
            0x01, // source_addr_ton (International)
            0x01, // source_addr_npi (ISDN)
            b'1', b'2', b'3', b'4', 0x00, // source_addr
            0x01, // dest_addr_ton (International)
            0x01, // dest_addr_npi (ISDN)
            b'5', b'6', b'7', b'8', 0x00, // destination_addr
            0x00, // esm_class
            0x00, // protocol_id
            0x00, // priority_flag
            0x00, // schedule_delivery_time (empty)
            0x00, // validity_period (empty)
            0x00, // registered_delivery
            0x00, // replace_if_present_flag
            0x00, // data_coding
            0x00, // sm_default_msg_id
            0x04, // sm_length (4 bytes)
            b'T', b'e', b's', b't', // short_message
            // TLV: user_message_reference
            0x02, 0x04, // tag (0x0204)
            0x00, 0x02, // length (2 bytes)
            0x00, 0x01, // value
            // TLV: source_port
            0x02, 0x0A, // tag (0x020A)
            0x00, 0x02, // length (2 bytes)
            0x1F, 0x90, // value (port 8080)
        ];

        let mut cursor = Cursor::new(data.as_slice());
        let result = Frame::parse(&mut cursor);

        assert!(result.is_ok());

        if let Frame::SubmitSm(submit_sm) = result.unwrap() {
            assert_eq!(submit_sm.short_message.as_str().unwrap(), "Test");
            assert_eq!(submit_sm.sm_length, 4);
            assert!(submit_sm.user_message_reference.is_some());
            assert!(submit_sm.source_port.is_some());

            let user_msg_ref = submit_sm.user_message_reference.unwrap();
            assert_eq!(user_msg_ref.tag, 0x0204);
            assert_eq!(user_msg_ref.length, 2);
            assert_eq!(user_msg_ref.value.as_ref(), &[0x00, 0x01]);

            let source_port = submit_sm.source_port.unwrap();
            assert_eq!(source_port.tag, 0x020A);
            assert_eq!(source_port.length, 2);
            assert_eq!(source_port.value.as_ref(), &[0x1F, 0x90]);
        } else {
            panic!("Expected SubmitSm frame");
        }
    }

    #[test]
    fn parse_submit_sm_empty_message_test() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x2F, // command_length (47 bytes)
            0x00, 0x00, 0x00, 0x04, // command_id (submit_sm)
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body:
            0x00, // service_type (empty)
            0x01, // source_addr_ton
            0x01, // source_addr_npi
            b'1', b'2', b'3', b'4', 0x00, // source_addr
            0x01, // dest_addr_ton
            0x01, // dest_addr_npi
            b'5', b'6', b'7', b'8', 0x00, // destination_addr
            0x00, // esm_class
            0x00, // protocol_id
            0x00, // priority_flag
            0x00, // schedule_delivery_time (empty)
            0x00, // validity_period (empty)
            0x00, // registered_delivery
            0x00, // replace_if_present_flag
            0x00, // data_coding
            0x00, // sm_default_msg_id
            0x00, // sm_length (0 bytes)
                  // No short_message data
        ];

        let mut cursor = Cursor::new(data.as_slice());
        let result = Frame::parse(&mut cursor);

        assert!(result.is_ok());

        if let Frame::SubmitSm(submit_sm) = result.unwrap() {
            assert_eq!(submit_sm.sm_length, 0);
            assert_eq!(submit_sm.short_message.as_str().unwrap(), "");
        } else {
            panic!("Expected SubmitSm frame");
        }
    }

    #[test]
    fn parse_submit_sm_error_invalid_sm_length() {
        use std::io::Cursor;

        let data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x2F, // command_length
            0x00, 0x00, 0x00, 0x04, // command_id (submit_sm)
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body:
            0x00, // service_type (empty)
            0x01, // source_addr_ton
            0x01, // source_addr_npi
            b'1', b'2', b'3', b'4', 0x00, // source_addr
            0x01, // dest_addr_ton
            0x01, // dest_addr_npi
            b'5', b'6', b'7', b'8', 0x00, // destination_addr
            0x00, // esm_class
            0x00, // protocol_id
            0x00, // priority_flag
            0x00, // schedule_delivery_time (empty)
            0x00, // validity_period (empty)
            0x00, // registered_delivery
            0x00, // replace_if_present_flag
            0x00, // data_coding
            0x00, // sm_default_msg_id
            0xFF, // sm_length (255 - invalid, exceeds max of 254)
        ];

        let mut cursor = Cursor::new(data.as_slice());
        let result = Frame::parse(&mut cursor);

        assert!(result.is_err());
    }

    #[test]
    fn submit_sm_roundtrip_test() {
        use crate::datatypes::{PriorityFlag, SubmitSm, ToBytes};

        let original = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 42,
            service_type: ServiceType::from("SMS"),
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
            registered_delivery: 1,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
            sm_default_msg_id: 0,
            sm_length: 13,
            short_message: ShortMessage::from("Hello, world!"),
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

        // Serialize to bytes
        let serialized = original.to_bytes();

        // Parse back from bytes
        let mut cursor = std::io::Cursor::new(serialized.as_ref());
        let parsed_frame = Frame::parse(&mut cursor).unwrap();

        // Verify it matches
        if let Frame::SubmitSm(parsed) = parsed_frame {
            assert_eq!(parsed.command_status, original.command_status);
            assert_eq!(parsed.sequence_number, original.sequence_number);
            assert_eq!(parsed.service_type, original.service_type);
            assert_eq!(parsed.source_addr_ton, original.source_addr_ton);
            assert_eq!(parsed.source_addr_npi, original.source_addr_npi);
            assert_eq!(parsed.source_addr, original.source_addr);
            assert_eq!(parsed.dest_addr_ton, original.dest_addr_ton);
            assert_eq!(parsed.dest_addr_npi, original.dest_addr_npi);
            assert_eq!(parsed.destination_addr, original.destination_addr);
            assert_eq!(parsed.esm_class, original.esm_class);
            assert_eq!(parsed.protocol_id, original.protocol_id);
            assert_eq!(parsed.priority_flag, original.priority_flag);
            assert_eq!(
                parsed.schedule_delivery_time,
                original.schedule_delivery_time
            );
            assert_eq!(parsed.validity_period, original.validity_period);
            assert_eq!(parsed.registered_delivery, original.registered_delivery);
            assert_eq!(
                parsed.replace_if_present_flag,
                original.replace_if_present_flag
            );
            assert_eq!(parsed.data_coding, original.data_coding);
            assert_eq!(parsed.sm_default_msg_id, original.sm_default_msg_id);
            assert_eq!(parsed.sm_length, original.sm_length);
            assert_eq!(parsed.short_message, original.short_message);
        } else {
            panic!("Expected SubmitSm frame");
        }
    }
}
