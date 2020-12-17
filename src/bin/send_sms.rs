use std::error::Error;
use tokio::net::{TcpStream, ToSocketAddrs};

use smpp::connection::Connection;
use smpp::datatypes::CommandStatus;
use smpp::datatypes::SubmitSm;
use smpp::datatypes::{BindTransmitter, NumericPlanIndicator, TypeOfNumber, Unbind};
use smpp::Frame;

/// Established connection with an SMSC.
///
/// Backed by a single `TcpStream`, `Client` provides basic network client
/// functionality (no pooling, retrying, ...). Connections are established using
/// the [`connect`](fn@connect) function.
///
/// Requests are issued using the various methods of `Client`.
pub struct Client {
    /// The TCP connection decorated with the SMPP protocol encoder / decoder
    /// implemented using a buffered `TcpStream`.
    ///
    /// When `Listener` receives an inbound connection, the `TcpStream` is
    /// passed to `Connection::new`, which initializes the associated buffers.
    /// `Connection` allows the handler to operate at the "frame" level and keep
    /// the byte level protocol parsing details encapsulated in `Connection`.
    connection: Connection,
}

impl Client {
    async fn bind(&mut self, system_id: String, password: String) -> Result<(), Box<dyn Error>> {
        let bind_transmitter = BindTransmitter {
            command_status: CommandStatus::Ok,
            sequence_number: 0,
            system_id,
            password,
            system_type: "".to_string(),
            interface_version: 0,
            addr_ton: TypeOfNumber::Unknown,
            addr_npi: NumericPlanIndicator::Unknown,
            address_range: "".to_string(),
        };

        println!("-> {:?}", &bind_transmitter);

        let frame = Frame::BindTransmitter(bind_transmitter);
        self.connection.write_frame(&frame).await.unwrap();

        //

        let response = match self.connection.read_frame().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error decoding bind response: {}", e);
                None
            }
        };

        println!("<-- {:?}", response);

        Ok(())
    }

    async fn unbind(&mut self) -> Result<(), Box<dyn Error>> {
        let unbind = Unbind {
            command_status: CommandStatus::Ok,
            sequence_number: 3,
        };
        let frame = Frame::Unbind(unbind);

        self.connection.write_frame(&frame).await?;

        Ok(())
    }

    async fn send(
        &mut self,
        to: String,
        from: String,
        message: String,
    ) -> Result<(), Box<dyn Error>> {
        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            service_type: "".to_string(),
            source_addr_ton: TypeOfNumber::Unknown,
            source_addr_npi: NumericPlanIndicator::Unknown,
            source_addr: from,
            dest_addr_ton: TypeOfNumber::Unknown,
            dest_addr_npi: NumericPlanIndicator::Unknown,
            destination_addr: to,
            esm_class: 0,
            protocol_id: 0,
            priority_flag: 0,
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

        let response = self.connection.read_frame().await.unwrap();

        println!("<- {:?}", response.unwrap());

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

    Ok(Client { connection })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let mut client = connect("192.168.86.27:2775").await?;

    let to = "123456789".to_string();
    let from = "123456789".to_string();
    let message = "Hello SMPP world!".to_string();

    client.bind("system_id".to_string(), "password".to_string()).await?;

    match client.send(to, from, message).await {
        Ok(_) => println!("Message sent"),
        Err(e) => eprintln!("An error has occurred: {}", e),
    };

    client.unbind().await
}
