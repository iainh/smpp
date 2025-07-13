// ABOUTME: Long-running SMPP client example demonstrating keep-alive functionality
// ABOUTME: Shows how to maintain connection health and handle failures in production applications

//! # Long-Running SMPP Client with Keep-Alive
//!
//! This example demonstrates how to create a long-running SMPP client that:
//! 
//! * Automatically monitors connection health using keep-alive
//! * Handles connection failures gracefully
//! * Optionally sends periodic SMS messages
//! * Provides comprehensive logging and statistics
//! * Shuts down cleanly on timeout or failure
//!
//! ## Usage
//!
//! ```bash
//! # Basic keep-alive monitoring (no SMS sending)
//! cargo run --example long_running_client -- --system-id test --password secret
//!
//! # With periodic SMS sending
//! cargo run --example long_running_client -- \
//!   --system-id test --password secret \
//!   --to 123456789 --from 987654321 \
//!   --sms-interval 120
//!
//! # Custom keep-alive settings
//! cargo run --example long_running_client -- \
//!   --system-id test --password secret \
//!   --keep-alive-interval 60 \
//!   --keep-alive-timeout 15 \
//!   --max-failures 5 \
//!   --run-duration 600
//! ```

use argh::FromArgs;
use smpp::client::{BindCredentials, DefaultClient, KeepAliveConfig, SmppClient, SmppConnection, SmppTransmitter, SmsMessage};
use std::error::Error;
use std::time::Duration;
use tokio::time::{interval, sleep};
use tracing::{Level, error, info, warn, debug};
use tracing_subscriber::FmtSubscriber;

/// Long-running SMPP client with keep-alive functionality
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

    /// keep-alive interval in seconds (default: 30)
    #[argh(option)]
    keep_alive_interval: Option<u64>,

    /// keep-alive timeout in seconds (default: 10)
    #[argh(option)]
    keep_alive_timeout: Option<u64>,

    /// maximum consecutive failures before considering connection dead (default: 3)
    #[argh(option)]
    max_failures: Option<u32>,

    /// how long to run the client in seconds (default: 300, i.e., 5 minutes)
    #[argh(option)]
    run_duration: Option<u64>,

    /// interval between SMS sends in seconds (default: 60)
    #[argh(option)]
    sms_interval: Option<u64>,

    /// the recipient telephone number (optional - no SMS sent if not provided)
    #[argh(option, short = 't')]
    to: Option<String>,

    /// the telephone number that the message will be from (optional)
    #[argh(option, short = 'f')]
    from: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli_args: CliArgs = argh::from_env();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(if cli_args.debugging { Level::DEBUG } else { Level::INFO })
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let host = cli_args.host.unwrap_or_else(|| "localhost".to_owned());
    let port = cli_args.port.unwrap_or(2775);
    let system_id = cli_args.system_id.unwrap_or_default();
    let password = cli_args.password.unwrap_or_default();
    let run_duration = Duration::from_secs(cli_args.run_duration.unwrap_or(300));
    let sms_interval = Duration::from_secs(cli_args.sms_interval.unwrap_or(60));

    info!("Starting long-running SMPP client");
    info!("Connecting to {host}:{port}");
    info!("Will run for {} seconds", run_duration.as_secs());

    // Create client and connect
    let mut client = DefaultClient::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| {
            error!("Connection failed: {e}");
            Box::<dyn Error>::from(e.to_string())
        })?;

    // Bind as transmitter
    let credentials = BindCredentials::transmitter(system_id, password);
    client.bind(&credentials).await.map_err(|e| {
        error!("Bind failed: {e}");
        Box::<dyn Error>::from(e.to_string())
    })?;

    info!("Connected and bound successfully");

    // Configure keep-alive
    let mut keep_alive_config = KeepAliveConfig::new(Duration::from_secs(
        cli_args.keep_alive_interval.unwrap_or(30)
    ));
    
    if let Some(timeout) = cli_args.keep_alive_timeout {
        keep_alive_config = keep_alive_config.with_timeout(Duration::from_secs(timeout));
    }
    
    if let Some(max_failures) = cli_args.max_failures {
        keep_alive_config = keep_alive_config.with_max_failures(max_failures);
    }

    // Start keep-alive
    client.start_keep_alive(keep_alive_config).await?;
    info!("Keep-alive started with interval {:?}", client.keep_alive_status().running);

    // Setup message sending if phone numbers are provided
    let send_messages = cli_args.to.is_some() && cli_args.from.is_some();
    let mut sms_timer = if send_messages {
        Some(interval(sms_interval))
    } else {
        None
    };

    // Setup keep-alive maintenance timer (check more frequently than the keep-alive interval)
    let keep_alive_check_interval = Duration::from_secs(5);
    let mut keep_alive_timer = interval(keep_alive_check_interval);

    // Main event loop
    let start_time = std::time::Instant::now();
    let mut message_count = 0;

    info!("Entering main loop");
    
    loop {
        tokio::select! {
            // Check if we should exit
            _ = sleep(run_duration.saturating_sub(start_time.elapsed())) => {
                info!("Run duration elapsed, shutting down");
                break;
            }
            
            // Maintain keep-alive
            _ = keep_alive_timer.tick() => {
                match client.maintain_keep_alive().await {
                    Ok(true) => debug!("Keep-alive ping sent"),
                    Ok(false) => debug!("Keep-alive ping not needed"),
                    Err(e) => {
                        warn!("Keep-alive ping failed: {}", e);
                    }
                }
                
                // Check if connection has failed
                if client.is_keep_alive_failed() {
                    error!("Connection failed due to keep-alive failures");
                    break;
                }
                
                // Log keep-alive status periodically
                let status = client.keep_alive_status();
                if status.total_pings > 0 && status.total_pings % 5 == 0 {
                    info!("Keep-alive status: pings={}, pongs={}, failures={}", 
                          status.total_pings, status.total_pongs, status.consecutive_failures);
                }
            }
            
            // Send SMS messages if configured
            _ = async {
                if let Some(ref mut timer) = sms_timer {
                    timer.tick().await;
                } else {
                    // If no SMS sending, wait forever
                    std::future::pending::<()>().await
                }
            } => {
                if let (Some(to), Some(from)) = (&cli_args.to, &cli_args.from) {
                    message_count += 1;
                    let message_text = format!("Test message #{} from long-running client", message_count);
                    let sms = SmsMessage::new(to, from, &message_text);
                    
                    match client.send_sms(&sms).await {
                        Ok(message_id) => {
                            info!("Message {} sent successfully! ID: {}", message_count, message_id);
                            
                            // Reset keep-alive failures on successful operations  
                            let status = client.keep_alive_status();
                            if status.consecutive_failures > 0 {
                                debug!("Resetting keep-alive failures after successful SMS send");
                            }
                        }
                        Err(e) => {
                            error!("Failed to send message {}: {}", message_count, e);
                        }
                    }
                }
            }
        }
    }

    // Shutdown sequence
    info!("Shutting down client");
    
    // Stop keep-alive
    if let Err(e) = client.stop_keep_alive().await {
        warn!("Failed to stop keep-alive: {}", e);
    }

    // Unbind gracefully
    if let Err(e) = client.unbind().await {
        warn!("Unbind failed: {}", e);
    }

    // Disconnect
    if let Err(e) = client.disconnect().await {
        warn!("Disconnect failed: {}", e);
    }

    // Print final statistics
    let final_status = client.keep_alive_status();
    info!("Final keep-alive statistics:");
    info!("  Total pings sent: {}", final_status.total_pings);
    info!("  Total pongs received: {}", final_status.total_pongs);
    info!("  Final consecutive failures: {}", final_status.consecutive_failures);
    info!("  Total SMS messages sent: {}", message_count);
    
    let uptime = start_time.elapsed();
    info!("Client ran for {:.1} seconds", uptime.as_secs_f64());

    Ok(())
}