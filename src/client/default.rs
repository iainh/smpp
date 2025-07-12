// ABOUTME: Default SMPP client implementation providing complete trait implementations
// ABOUTME: Based on the robust example client with proper error handling and response validation

use crate::client::error::{SmppError, SmppResult};
use crate::client::traits::{SmppClient, SmppConnection, SmppTransmitter};
use crate::client::types::{BindCredentials, BindType, SmsMessage};
use crate::connection::Connection;
use crate::datatypes::*;
use crate::Frame;
use tokio::net::{TcpStream, ToSocketAddrs};

/// Default SMPP client implementation
///
/// Provides a complete implementation of all SMPP client traits with
/// proper error handling, response validation, and sequence number management.
/// Based on the robust send_sms example with improvements for production use.
pub struct DefaultClient {
    /// The TCP connection with SMPP protocol frame handling
    connection: Connection,
    /// Sequence number for PDU correlation
    sequence_number: u32,
    /// Current connection state
    connected: bool,
}

impl SmppConnection for DefaultClient {
    async fn connect<T: ToSocketAddrs>(addr: T) -> SmppResult<Self> {
        let socket = TcpStream::connect(addr).await?;
        let connection = Connection::new(socket);

        Ok(DefaultClient {
            connection,
            sequence_number: 0,
            connected: true,
        })
    }

    async fn disconnect(&mut self) -> SmppResult<()> {
        // Note: Connection doesn't expose close method, so we just mark as disconnected
        // The underlying TcpStream will be dropped when Connection is dropped
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

impl SmppClient for DefaultClient {
    async fn bind(&mut self, credentials: &BindCredentials) -> SmppResult<()> {
        if !self.connected {
            return Err(SmppError::InvalidState("Not connected".to_string()));
        }

        self.sequence_number += 1;

        let frame = match credentials.bind_type {
            BindType::Transmitter => {
                let bind_transmitter = BindTransmitter {
                    command_status: CommandStatus::Ok,
                    sequence_number: self.sequence_number,
                    system_id: SystemId::from(credentials.system_id.as_str()),
                    password: Some(Password::from(credentials.password.as_str())),
                    system_type: SystemType::from(credentials.system_type.as_deref().unwrap_or("")),
                    interface_version: InterfaceVersion::SmppV34,
                    addr_ton: TypeOfNumber::Unknown,
                    addr_npi: NumericPlanIndicator::Unknown,
                    address_range: AddressRange::default(),
                };
                Frame::BindTransmitter(bind_transmitter)
            }
            BindType::Receiver => {
                let bind_receiver = BindReceiver {
                    command_status: CommandStatus::Ok,
                    sequence_number: self.sequence_number,
                    system_id: SystemId::from(credentials.system_id.as_str()),
                    password: Some(Password::from(credentials.password.as_str())),
                    system_type: SystemType::from(credentials.system_type.as_deref().unwrap_or("")),
                    interface_version: InterfaceVersion::SmppV34,
                    addr_ton: TypeOfNumber::Unknown,
                    addr_npi: NumericPlanIndicator::Unknown,
                    address_range: AddressRange::default(),
                };
                Frame::BindReceiver(bind_receiver)
            }
            BindType::Transceiver => {
                let bind_transceiver = BindTransceiver {
                    command_status: CommandStatus::Ok,
                    sequence_number: self.sequence_number,
                    system_id: SystemId::from(credentials.system_id.as_str()),
                    password: Some(Password::from(credentials.password.as_str())),
                    system_type: SystemType::from(credentials.system_type.as_deref().unwrap_or("")),
                    interface_version: InterfaceVersion::SmppV34,
                    addr_ton: TypeOfNumber::Unknown,
                    addr_npi: NumericPlanIndicator::Unknown,
                    address_range: AddressRange::default(),
                };
                Frame::BindTransceiver(bind_transceiver)
            }
        };

        self.connection
            .write_frame(&frame)
            .await
            .map_err(|e| SmppError::Connection(e))?;

        // Wait for and validate bind response
        match self.connection.read_frame().await {
            Ok(Some(response)) => {
                let command_status = match &response {
                    Frame::BindTransmitterResponse(resp) => resp.command_status,
                    Frame::BindReceiverResponse(resp) => resp.command_status,
                    Frame::BindTransceiverResponse(resp) => resp.command_status,
                    other => {
                        return Err(SmppError::UnexpectedPdu {
                            expected: format!("Bind{:?}Response", credentials.bind_type),
                            actual: format!("{:?}", other),
                        });
                    }
                };

                if command_status != CommandStatus::Ok {
                    return Err(SmppError::Protocol(command_status));
                }

                Ok(())
            }
            Ok(None) => Err(SmppError::ConnectionClosed),
            Err(e) => Err(SmppError::from(e)),
        }
    }

    async fn unbind(&mut self) -> SmppResult<()> {
        if !self.connected {
            return Err(SmppError::InvalidState("Not connected".to_string()));
        }

        self.sequence_number += 1;

        let unbind = Unbind {
            command_status: CommandStatus::Ok,
            sequence_number: self.sequence_number,
        };

        let frame = Frame::Unbind(unbind);
        self.connection
            .write_frame(&frame)
            .await
            .map_err(|e| SmppError::Connection(e))?;

        // Wait for unbind response
        match self.connection.read_frame().await {
            Ok(Some(Frame::UnbindResponse(response))) => {
                if response.command_status != CommandStatus::Ok {
                    return Err(SmppError::Protocol(response.command_status));
                }
                Ok(())
            }
            Ok(Some(other)) => Err(SmppError::UnexpectedPdu {
                expected: "UnbindResponse".to_string(),
                actual: format!("{:?}", other),
            }),
            Ok(None) => {
                // Connection closed during unbind is acceptable
                Ok(())
            }
            Err(e) => Err(SmppError::from(e)),
        }
    }

    async fn enquire_link(&mut self) -> SmppResult<()> {
        if !self.connected {
            return Err(SmppError::InvalidState("Not connected".to_string()));
        }

        self.sequence_number += 1;

        let enquire_link = EnquireLink {
            sequence_number: self.sequence_number,
        };

        let frame = Frame::EnquireLink(enquire_link);
        self.connection
            .write_frame(&frame)
            .await
            .map_err(|e| SmppError::Connection(e))?;

        // Wait for enquire_link response
        match self.connection.read_frame().await {
            Ok(Some(Frame::EnquireLinkResponse(_response))) => {
                // EnquireLinkResponse doesn't have command_status field - it's always OK
                Ok(())
            }
            Ok(Some(other)) => Err(SmppError::UnexpectedPdu {
                expected: "EnquireLinkResponse".to_string(),
                actual: format!("{:?}", other),
            }),
            Ok(None) => Err(SmppError::ConnectionClosed),
            Err(e) => Err(SmppError::from(e)),
        }
    }

    fn next_sequence_number(&mut self) -> u32 {
        self.sequence_number += 1;
        self.sequence_number
    }
}

impl SmppTransmitter for DefaultClient {
    async fn send_sms(&mut self, message: &SmsMessage) -> SmppResult<String> {
        // Validate message length for short_message field
        if message.text.len() > 254 {
            return Err(SmppError::InvalidData(
                "Message too long (>254 bytes). Use submit_sm with message_payload TLV for longer messages.".to_string()
            ));
        }

        let sequence_number = self.next_sequence_number();

        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number,
            service_type: ServiceType::default(),
            source_addr_ton: message.options.source_ton,
            source_addr_npi: message.options.source_npi,
            source_addr: SourceAddr::new(&message.from, message.options.source_ton)
                .unwrap_or_default(),
            dest_addr_ton: message.options.dest_ton,
            dest_addr_npi: message.options.dest_npi,
            destination_addr: DestinationAddr::new(&message.to, message.options.dest_ton)
                .unwrap_or_default(),
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: message.options.priority,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: message.options.registered_delivery,
            replace_if_present_flag: 0,
            data_coding: message.options.data_coding,
            sm_default_msg_id: 0,
            sm_length: message.text.len() as u8,
            short_message: ShortMessage::from(message.text.as_str()),
            // TLV parameters - set to None for basic messages
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

        self.submit_sm(&submit_sm).await
    }

    async fn submit_sm(&mut self, submit: &SubmitSm) -> SmppResult<String> {
        if !self.connected {
            return Err(SmppError::InvalidState("Not connected".to_string()));
        }

        let frame = Frame::SubmitSm(Box::new(submit.clone()));
        self.connection
            .write_frame(&frame)
            .await
            .map_err(|e| SmppError::Connection(e))?;

        // Wait for and validate submit response
        match self.connection.read_frame().await {
            Ok(Some(Frame::SubmitSmResponse(response))) => {
                if response.command_status != CommandStatus::Ok {
                    return Err(SmppError::Protocol(response.command_status));
                }
                Ok(response.message_id.to_string())
            }
            Ok(Some(other)) => Err(SmppError::UnexpectedPdu {
                expected: "SubmitSmResponse".to_string(),
                actual: format!("{:?}", other),
            }),
            Ok(None) => Err(SmppError::ConnectionClosed),
            Err(e) => Err(SmppError::from(e)),
        }
    }
}
