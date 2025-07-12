pub(crate) use argh::FromArgs;
use smpp::connection::Connection;
use smpp::datatypes::SubmitSm;
use smpp::datatypes::{BindTransmitter, NumericPlanIndicator, TypeOfNumber, Unbind, SystemId, Password, SystemType, AddressRange};
use smpp::datatypes::{CommandStatus, InterfaceVersion, PriorityFlag, ServiceType, SourceAddr, DestinationAddr, ScheduleDeliveryTime, ValidityPeriod, ShortMessage, EsmClass, DataCoding};
use smpp::Frame;
use std::error::Error;
use tokio::net::{TcpStream, ToSocketAddrs};

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

    /// The most recently used sequence number.
    sequence_number: u32,
}

impl Client {
    async fn bind(&mut self, system_id: &str, password: &str) -> Result<(), Box<dyn Error>> {
        self.sequence_number += 1;

        let bind_transmitter = BindTransmitter {
            command_status: CommandStatus::Ok, // Will be set to 0 in to_bytes() for requests
            sequence_number: self.sequence_number,
            system_id: SystemId::from(system_id),
            password: Some(Password::from(password)),
            system_type: SystemType::default(),
            interface_version: InterfaceVersion::SmppV34,
            addr_ton: TypeOfNumber::Unknown,
            addr_npi: NumericPlanIndicator::Unknown,
            address_range: AddressRange::default(),
        };

        println!("-> {bind_transmitter:?}");

        let frame = Frame::BindTransmitter(bind_transmitter);
        self.connection.write_frame(&frame).await?;

        // Wait for and validate bind response
        match self.connection.read_frame().await {
            Ok(Some(Frame::BindTransmitterResponse(response))) => {
                println!("<- {response:?}");
                if response.command_status != CommandStatus::Ok {
                    return Err(
                        format!("Bind failed with status: {:?}", response.command_status).into(),
                    );
                }
                println!("Bind successful");
            }
            Ok(Some(other)) => {
                return Err(format!("Expected BindTransmitterResponse, got {other:?}").into());
            }
            Ok(None) => {
                return Err("Connection closed during bind".into());
            }
            Err(e) => {
                return Err(format!("Error reading bind response: {e}").into());
            }
        }

        Ok(())
    }

    async fn send(
        &mut self,
        to: &str,
        from: &str,
        message: &str,
    ) -> Result<String, Box<dyn Error>> {
        // Validate message length
        if message.len() > 254 {
            return Err(
                "Message too long (>254 bytes). Use message_payload TLV for longer messages."
                    .into(),
            );
        }

        self.sequence_number += 1;

        let submit_sm = SubmitSm {
            command_status: CommandStatus::Ok, // Will be set to 0 in to_bytes() for requests
            sequence_number: self.sequence_number,
            service_type: ServiceType::default(),
            source_addr_ton: TypeOfNumber::Unknown,
            source_addr_npi: NumericPlanIndicator::Unknown,
            source_addr: SourceAddr::new(from, TypeOfNumber::Unknown).unwrap_or_default(),
            dest_addr_ton: TypeOfNumber::Unknown,
            dest_addr_npi: NumericPlanIndicator::Unknown,
            destination_addr: DestinationAddr::new(to, TypeOfNumber::Unknown).unwrap_or_default(),
            esm_class: EsmClass::default(),
            protocol_id: 0,
            priority_flag: PriorityFlag::Level0,
            schedule_delivery_time: ScheduleDeliveryTime::default(),
            validity_period: ValidityPeriod::default(),
            registered_delivery: 0,
            replace_if_present_flag: 0,
            data_coding: DataCoding::default(),
            sm_default_msg_id: 0,
            sm_length: message.len() as u8,
            short_message: ShortMessage::from(message),
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

        println!("-> {submit_sm:?}");

        let frame = Frame::SubmitSm(Box::new(submit_sm));
        self.connection.write_frame(&frame).await?;

        // Wait for and validate submit response
        match self.connection.read_frame().await {
            Ok(Some(Frame::SubmitSmResponse(response))) => {
                println!("<- {response:?}");
                if response.command_status != CommandStatus::Ok {
                    return Err(format!(
                        "Submit failed with status: {:?}",
                        response.command_status
                    )
                    .into());
                }
                println!("Message submitted successfully");
                Ok(response.message_id.to_string())
            }
            Ok(Some(other)) => Err(format!("Expected SubmitSmResponse, got {other:?}").into()),
            Ok(None) => Err("Connection closed during submit".into()),
            Err(e) => Err(format!("Error reading submit response: {e}").into()),
        }
    }

    async fn unbind(&mut self) -> Result<(), Box<dyn Error>> {
        self.sequence_number += 1;

        let unbind = Unbind {
            command_status: CommandStatus::Ok, // Will be set to 0 in to_bytes() for requests
            sequence_number: self.sequence_number,
        };

        println!("-> {unbind:?}");

        let frame = Frame::Unbind(unbind);
        self.connection.write_frame(&frame).await?;

        // Wait for unbind response
        match self.connection.read_frame().await {
            Ok(Some(Frame::UnbindResponse(response))) => {
                println!("<- {response:?}");
                if response.command_status != CommandStatus::Ok {
                    return Err(format!(
                        "Unbind failed with status: {:?}",
                        response.command_status
                    )
                    .into());
                }
                println!("Unbind successful");
            }
            Ok(Some(other)) => {
                return Err(format!("Expected UnbindResponse, got {other:?}").into());
            }
            Ok(None) => {
                println!("Connection closed during unbind (this may be normal)");
            }
            Err(e) => {
                return Err(format!("Error reading unbind response: {e}").into());
            }
        }

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

/// Example application to show then simplest case of sending an SMS message
#[derive(FromArgs)]
struct CliArgs {
    /// whether or not to enable debugging
    #[argh(switch, short = 'd')]
    debugging: bool,

    /// the system id
    #[argh(option)]
    system_id: Option<String>,

    /// the password
    #[argh(option)]
    password: Option<String>,

    /// the hostname of IP address of the SMSC (default: localhost)
    #[argh(option)]
    host: Option<String>,

    /// the port to use when connecting to the SMSC (default: 2775)
    #[argh(option, short = 'p')]
    port: Option<u32>,

    /// the message to send
    #[argh(option, short = 'm')]
    message: String,

    /// the recipient telephone number
    #[argh(option, short = 't')]
    to: String,

    /// the telephone number that the message will be from
    #[argh(option, short = 'f')]
    from: String,
}

use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli_args: CliArgs = argh::from_env();

    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::TRACE)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let debugging = cli_args.debugging;
    let host = cli_args.host.unwrap_or_else(|| "localhost".to_owned());
    let port = cli_args.port.unwrap_or(2775);
    let system_id = cli_args.system_id.unwrap_or_default();
    let password = cli_args.password.unwrap_or_default();

    let to = cli_args.to;
    let from = cli_args.from;
    let message = cli_args.message;

    if debugging {
        println!("Connecting to {host}:{port}");
    }

    let mut client = connect(format!("{host}:{port}")).await?;

    // Bind to SMSC
    client.bind(&system_id, &password).await.map_err(|e| {
        eprintln!("Bind failed: {e}");
        e
    })?;

    // Send message
    let unbind_result = match client.send(&to, &from, &message).await {
        Ok(message_id) => {
            println!("Message sent successfully! Message ID: {message_id}");
            client.unbind().await
        }
        Err(e) => {
            eprintln!("Failed to send message: {e}");
            // Still attempt to unbind cleanly
            match client.unbind().await {
                Ok(_) => Err(e),
                Err(unbind_err) => {
                    eprintln!("Also failed to unbind: {unbind_err}");
                    Err(e) // Return original error
                }
            }
        }
    };

    unbind_result
}
