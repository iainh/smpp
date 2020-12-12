use smpp::datatypes::{BindTransmitter, BindTransmitterResponse, Tlv};
use smpp::CommandId;
use smpp::CommandStatus;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to a peer
    // let mut stream = TcpStream::connect("192.168.86.27:8080").await?;

    // Write some data.
    // stream.write_all(b"hello world!").await?;

    let bind_transmitter = BindTransmitter {
        command_status: CommandStatus::Ok,
        sequence_number: 1,
        system_id: "system_id".to_string(),
        password: "password".to_string(),
        system_type: "system_type".to_string(),
        interface_version: 10,
        addr_ton: 20,
        addr_npi: 30,
        address_range: "address_range".to_string(),
    };

    let bind_transmitter_response = BindTransmitterResponse {
        command_id: CommandId::GenericNack,
        command_status: CommandStatus::Ok,
        sequence_number: 1,
        system_id: "system_id".to_string(),
        sc_interface_version: Some(Tlv {
            tag: "something".to_string(),
            length: 2,
            value: Default::default(),
        }),
    };

    Ok(())
}
