use tokio::net::{TcpStream, ToSocketAddrs};

use crate::{connection::Connection, datatypes::*, Frame};
use std::error::Error;

pub struct Client {
    /// The TCP connection decorated with the SMPP protocol encoder / decoder
    /// implemented using a buffered `TcpStream`.
    ///
    /// When `Listener` receives an inbound connection, the `TcpStream` is
    /// passed to `Connection::new`, which initializes the associated buffers.
    /// `Connection` allows the handler to operate at the "frame" level and keep
    /// the byte level protocol parsing details encapsulated in `Connection`.
    connection: Connection,

    /// The most recently used sequence number.
    sequence_number: u32,
}

impl Client {
    async fn bind(&mut self, system_id: &str, password: &str) -> Result<(), Box<dyn Error>> {
        self.sequence_number += 1;

        let bind_transmitter = BindTransmitter {
            command_status: CommandStatus::Ok,
            sequence_number: self.sequence_number,
            system_id: system_id.to_string(),
            password: Some(password.to_string()),
            system_type: "".to_string(),
            interface_version: InterfaceVersion::SmppV34,
            addr_ton: TypeOfNumber::Unknown,
            addr_npi: NumericPlanIndicator::Unknown,
            address_range: "".to_string(),
        };

        println!("-> {:?}", &bind_transmitter);

        let frame = Frame::BindTransmitter(bind_transmitter);
        self.connection.write_frame(&frame).await?;

        match self.connection.read_frame().await {
            Ok(r) => println!("<- {:?}", r),
            Err(e) => {
                eprintln!("Error decoding bind response: {}", e);
            }
        };

        Ok(())
    }

    async fn send(
        &mut self,
        to: String,
        from: String,
        message: String,
    ) -> Result<(), Box<dyn Error>> {
        self.sequence_number += 1;

        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: self.sequence_number,
            service_type: "".to_string(),
            source_addr_ton: TypeOfNumber::Unknown,
            source_addr_npi: NumericPlanIndicator::Unknown,
            source_addr: from,
            dest_addr_ton: TypeOfNumber::Unknown,
            dest_addr_npi: NumericPlanIndicator::Unknown,
            destination_addr: to,
            esm_class: 0,
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: "".to_string(),
            validity_period: "".to_string(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: 0,
            sm_default_msg_id: 0,
            sm_length: message.len() as u8,
            short_message: message,
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

        println!("-> {:?}", &submit_sm);

        let frame = Frame::SubmitSm(Box::new(submit_sm));
        self.connection.write_frame(&frame).await?;

        match self.connection.read_frame().await {
            Ok(response) => {
                if let Some(response) = response {
                    println!("<- {:?}", response);
                }
            }
            Err(e) => {
                eprintln!("Error response from send_sm: {}", e)
            }
        }

        Ok(())
    }

    async fn unbind(&mut self) -> Result<(), Box<dyn Error>> {
        self.sequence_number += 1;

        let unbind = Unbind {
            command_status: CommandStatus::Ok,
            sequence_number: self.sequence_number,
        };

        let frame = Frame::Unbind(unbind);

        self.connection.write_frame(&frame).await?;

        Ok(())
    }
}

pub async fn connect<T: ToSocketAddrs>(addr: T) -> Result<Client, Box<dyn Error>> {
    // The `addr` argument is passed directly to `TcpStream::connect`. This
    // performs any asynchronous DNS lookup and attempts to establish the TCP
    // connection. An error at either step returns an error, which is then
    // bubbled up to the caller of `mini_redis` connect.
    let socket = TcpStream::connect(addr).await?;

    // Initialize the connection state. This allocates read/write buffers to
    // perform redis protocol frame parsing.
    let connection = Connection::new(socket);

    Ok(Client {
        connection,
        sequence_number: 0,
    })
}
