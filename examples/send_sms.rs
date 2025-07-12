// ABOUTME: Example application demonstrating SMS sending using the trait-based SMPP client API
// ABOUTME: Shows usage of ClientBuilder::quick_transmitter for simple connection and bind flow

pub(crate) use argh::FromArgs;
use smpp::client::{ClientBuilder, SmppClient, SmppConnection, SmppTransmitter, SmsMessage};
use std::error::Error;

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

    // Use the new trait-based client API
    let mut client =
        ClientBuilder::quick_transmitter(format!("{host}:{port}"), system_id, password)
            .await
            .map_err(|e| {
                eprintln!("Connection/bind failed: {e}");
                Box::<dyn Error>::from(e.to_string())
            })?;

    println!("Connected and bound successfully");

    // Create SMS message using the builder
    let sms = SmsMessage::new(&to, &from, &message);

    // Send message
    match client.send_sms(&sms).await {
        Ok(message_id) => {
            println!("Message sent successfully! Message ID: {message_id}");

            // Clean shutdown
            if let Err(e) = client.unbind().await {
                eprintln!("Warning: Unbind failed: {e}");
            }

            if let Err(e) = client.disconnect().await {
                eprintln!("Warning: Disconnect failed: {e}");
            }

            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to send message: {e}");

            // Still attempt to unbind cleanly
            let _ = client.unbind().await;
            let _ = client.disconnect().await;

            Err(Box::<dyn Error>::from(e.to_string()))
        }
    }
}
