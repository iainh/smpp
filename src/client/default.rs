// ABOUTME: Default SMPP client implementation providing complete trait implementations
// ABOUTME: Based on the robust example client with proper error handling and response validation

use crate::Frame;
use crate::client::error::{SmppError, SmppResult};
use crate::client::keepalive::{KeepAliveConfig, KeepAliveManager, KeepAliveStatus};
use crate::client::traits::{SmppClient, SmppConnection, SmppTransmitter};
use crate::client::types::{BindCredentials, BindType, SmsMessage};
use crate::connection::Connection;
use crate::datatypes::*;
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
    /// Keep-alive manager for automatic enquire_link handling
    keep_alive: Option<KeepAliveManager>,
}

impl SmppConnection for DefaultClient {
    async fn connect<T: ToSocketAddrs + Send>(addr: T) -> SmppResult<Self> {
        let socket = TcpStream::connect(addr).await?;
        let connection = Connection::new(socket);

        Ok(DefaultClient {
            connection,
            sequence_number: 0,
            connected: true,
            keep_alive: None,
        })
    }

    async fn disconnect(&mut self) -> SmppResult<()> {
        // Disable keep-alive if running
        if let Some(keep_alive) = &mut self.keep_alive {
            keep_alive.disable();
        }
        self.keep_alive = None;
        
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
            .map_err(SmppError::Connection)?;

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
                            actual: format!("{other:?}"),
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
            .map_err(SmppError::Connection)?;

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
                actual: format!("{other:?}"),
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

        // Record that we're sending a ping
        if let Some(keep_alive) = &mut self.keep_alive {
            keep_alive.on_ping_sent();
        }

        self.sequence_number += 1;

        let enquire_link = EnquireLink {
            sequence_number: self.sequence_number,
        };

        let frame = Frame::EnquireLink(enquire_link);
        self.connection
            .write_frame(&frame)
            .await
            .map_err(SmppError::Connection)?;

        // Wait for enquire_link response
        match self.connection.read_frame().await {
            Ok(Some(Frame::EnquireLinkResponse(_response))) => {
                // EnquireLinkResponse doesn't have command_status field - it's always OK
                
                // Record successful ping
                if let Some(keep_alive) = &mut self.keep_alive {
                    keep_alive.on_ping_success();
                }
                
                Ok(())
            }
            Ok(Some(other)) => {
                // Record failed ping
                if let Some(keep_alive) = &mut self.keep_alive {
                    keep_alive.on_ping_failure();
                }
                Err(SmppError::UnexpectedPdu {
                    expected: "EnquireLinkResponse".to_string(),
                    actual: format!("{other:?}"),
                })
            }
            Ok(None) => {
                // Record failed ping
                if let Some(keep_alive) = &mut self.keep_alive {
                    keep_alive.on_ping_failure();
                }
                Err(SmppError::ConnectionClosed)
            }
            Err(e) => {
                // Record failed ping
                if let Some(keep_alive) = &mut self.keep_alive {
                    keep_alive.on_ping_failure();
                }
                Err(SmppError::from(e))
            }
        }
    }

    async fn start_keep_alive(&mut self, config: KeepAliveConfig) -> SmppResult<()> {
        if !self.connected {
            return Err(SmppError::InvalidState("Not connected".to_string()));
        }

        // Create and enable the keep-alive manager
        let manager = KeepAliveManager::new(config);
        self.keep_alive = Some(manager);
        
        Ok(())
    }

    async fn stop_keep_alive(&mut self) -> SmppResult<()> {
        if let Some(keep_alive) = &mut self.keep_alive {
            keep_alive.disable();
        }
        self.keep_alive = None;
        Ok(())
    }

    fn keep_alive_status(&self) -> KeepAliveStatus {
        self.keep_alive
            .as_ref()
            .map(|ka| ka.status())
            .unwrap_or(KeepAliveStatus {
                running: false,
                consecutive_failures: 0,
                total_pings: 0,
                total_pongs: 0,
            })
    }

    fn next_sequence_number(&mut self) -> u32 {
        self.sequence_number += 1;
        self.sequence_number
    }
}

impl DefaultClient {
    /// Check if a keep-alive ping should be sent and send it if needed
    ///
    /// This is a convenience method that integrates the keep-alive manager
    /// with the enquire_link functionality. Call this periodically in
    /// long-running applications to automatically maintain connection health.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - An enquire_link was sent successfully
    /// * `Ok(false)` - No ping was needed (too soon, disabled, or max failures reached)
    /// * `Err(SmppError)` - The enquire_link failed
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use smpp::client::{DefaultClient, KeepAliveConfig, SmppClient, SmppConnection};
    /// # use std::time::Duration;
    /// # use tokio::time::sleep;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = DefaultClient::connect("localhost:2775").await?;
    /// client.start_keep_alive(KeepAliveConfig::default()).await?;
    /// 
    /// loop {
    ///     // Your application logic here
    ///     
    ///     // Maintain keep-alive (typically called every few seconds)
    ///     match client.maintain_keep_alive().await {
    ///         Ok(true) => println!("Keep-alive ping sent"),
    ///         Ok(false) => {}, // No ping needed
    ///         Err(e) => {
    ///             eprintln!("Keep-alive failed: {}", e);
    ///             break; // Consider reconnecting
    ///         }
    ///     }
    ///     
    ///     sleep(Duration::from_secs(5)).await;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn maintain_keep_alive(&mut self) -> SmppResult<bool> {
        if let Some(keep_alive) = &self.keep_alive {
            if keep_alive.should_ping() {
                self.enquire_link().await?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    
    /// Check if the connection has failed due to keep-alive failures
    ///
    /// Returns true if the configured maximum number of consecutive
    /// keep-alive failures has been reached. When this occurs, the
    /// connection should typically be considered dead and re-established.
    ///
    /// # Returns
    ///
    /// * `true` - Connection has failed based on keep-alive metrics
    /// * `false` - Connection appears healthy or keep-alive is disabled
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use smpp::client::{DefaultClient, KeepAliveConfig, SmppClient, SmppConnection};
    /// # use std::time::Duration;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = DefaultClient::connect("localhost:2775").await?;
    /// 
    /// let config = KeepAliveConfig::default().with_max_failures(3);
    /// client.start_keep_alive(config).await?;
    /// 
    /// loop {
    ///     client.maintain_keep_alive().await.ok(); // Ignore errors for this example
    ///     
    ///     if client.is_keep_alive_failed() {
    ///         println!("Connection failed, attempting reconnect...");
    ///         // Reconnection logic here
    ///         break;
    ///     }
    ///     
    ///     // Continue with application logic
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_keep_alive_failed(&self) -> bool {
        self.keep_alive
            .as_ref()
            .map(|ka| ka.is_connection_failed())
            .unwrap_or(false)
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
            .map_err(SmppError::Connection)?;

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
                actual: format!("{other:?}"),
            }),
            Ok(None) => Err(SmppError::ConnectionClosed),
            Err(e) => Err(SmppError::from(e)),
        }
    }
}
