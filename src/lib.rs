pub mod client;
pub mod codec;
pub mod connection;
pub mod datatypes;
pub mod frame;

#[cfg(test)]
mod tests;

// Re-export frame types (which now come from codec)

// Re-export codec types for direct access
pub use codec::{CodecError, Decodable, Encodable, Frame, PduHeader, PduRegistry};

// Re-export the main client API for easy access
pub use client::{
    BindCredentials, ClientBuilder, SmppClient, SmppConnection, SmppError, SmppResult,
    SmppTransmitter, SmsMessage,
};

/// Error returned by most functions.
///
/// When writing a real application, one might want to consider a specialized
/// error handling crate or defining an error type as an `enum` of causes.
/// However, for our example, using a boxed `std::error::Error` is sufficient.
///
/// For performance reasons, boxing is avoided in any hot path. For example, in
/// `parse`, a custom error `enum` is defined. This is because the error is hit
/// and handled during normal execution when a partial frame is received on a
/// socket. `std::error::Error` is implemented for `parse::Error` which allows
/// it to be converted to `Box<dyn std::error::Error>`.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// A specialized `Result` type for SMPP operations.
///
/// This is defined as a convenience.
///
/// # Examples
///
/// ## Basic SMS Sending
///
/// This example shows the simplest way to send an SMS message using the SMPP client:
///
/// ```rust,no_run
/// use smpp::client::{ClientBuilder, SmppClient, SmppConnection, SmppTransmitter, SmsMessage};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Connect and bind as transmitter (Section 4.1 - Bind Operations)
///     let mut client = ClientBuilder::quick_transmitter(
///         "localhost:2775",
///         "system_id",
///         "password"
///     ).await?;
///
///     // Create SMS message
///     let sms = SmsMessage::new("1234567890", "0987654321", "Hello, World!");
///
///     // Send SMS message (Section 4.4.1 - submit_sm)
///     let message_id = client.send_sms(&sms).await?;
///
///     println!("Message sent with ID: {}", message_id);
///
///     // Clean disconnect (Section 4.2.1 - unbind)
///     client.unbind().await?;
///     client.disconnect().await?;
///
///     Ok(())
/// }
/// ```
///
/// ## Advanced Usage with Message Options
///
/// This example demonstrates using the message builder with advanced options:
///
/// ```rust,no_run
/// use smpp::client::{ClientBuilder, SmppClient, SmppConnection, SmppTransmitter, SmsMessage};
/// use smpp::datatypes::{TypeOfNumber, NumericPlanIndicator, PriorityFlag, DataCoding};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Connect and bind as transmitter
///     let mut client = ClientBuilder::quick_transmitter(
///         "localhost:2775",
///         "system_id",
///         "password"
///     ).await?;
///
///     // Create SMS with advanced options
///     let sms = SmsMessage::builder()
///         .to("1234567890")
///         .from("0987654321")
///         .text("Hello with options!")
///         .priority(PriorityFlag::Level1)
///         .data_coding(DataCoding::default())
///         .with_delivery_receipt()
///         .source_numbering(TypeOfNumber::International, NumericPlanIndicator::Isdn)
///         .dest_numbering(TypeOfNumber::International, NumericPlanIndicator::Isdn)
///         .build()?;
///
///     // Send message
///     let message_id = client.send_sms(&sms).await?;
///     println!("Message sent with ID: {}", message_id);
///
///     // Clean disconnect
///     client.unbind().await?;
///     client.disconnect().await?;
///
///     Ok(())
/// }
/// ```
pub type Result<T> = std::result::Result<T, Error>;
