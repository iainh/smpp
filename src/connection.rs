// ABOUTME: Provides TCP connection management for SMPP v3.4 protocol communication
// ABOUTME: Implements frame-based I/O with buffering for optimal network performance

use crate::codec::Encodable;
use crate::frame::{self, Frame};
use bytes::{Buf, BytesMut};
use std::io::{self, Cursor};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;

/// SMPP v3.4 Connection Management
///
/// Handles frame-based communication over TCP for SMPP protocol sessions.
/// This implements the transport layer for SMPP v3.4 as defined in Section 2.1
/// of the specification.
///
/// ## SMPP v3.4 Session States (Section 2.1)
///
/// An SMPP session progresses through the following states:
///
/// ```text
/// CLOSED → OPEN → BOUND_TX/BOUND_RX/BOUND_TRX → UNBOUND → CLOSED
/// ```
///
/// ### State Descriptions
/// - **CLOSED**: No TCP connection exists
/// - **OPEN**: TCP connection established but no SMPP bind completed  
/// - **BOUND_TX**: Successfully bound as transmitter (can send submit_sm)
/// - **BOUND_RX**: Successfully bound as receiver (can receive deliver_sm)
/// - **BOUND_TRX**: Successfully bound as transceiver (both TX and RX capabilities)
/// - **UNBOUND**: Unbind initiated, session terminating
///
/// ## Valid PDU Sequences by State (Section 2.1.1)
///
/// ### OPEN State (after TCP connect, before bind)
/// - **Allowed**: bind_transmitter, bind_receiver, bind_transceiver, outbind
/// - **Responses**: bind_*_resp, generic_nack
///
/// ### BOUND_TX State  
/// - **Allowed**: submit_sm, query_sm, cancel_sm, replace_sm, enquire_link, unbind
/// - **Responses**: submit_sm_resp, query_sm_resp, cancel_sm_resp, replace_sm_resp, enquire_link_resp, unbind_resp, generic_nack
///
/// ### BOUND_RX State
/// - **Allowed**: enquire_link, unbind  
/// - **Received**: deliver_sm, alert_notification
/// - **Responses**: deliver_sm_resp, enquire_link_resp, unbind_resp, generic_nack
///
/// ### BOUND_TRX State
/// - **Allowed**: All TX and RX operations combined
///
/// ## Connection Lifecycle
/// 1. TCP connection established (CLOSED → OPEN)
/// 2. Bind operation performed (OPEN → BOUND_*)  
/// 3. Message exchange in bound state
/// 4. Unbind operation (BOUND_* → UNBOUND)
/// 5. TCP connection closed (UNBOUND → CLOSED)
///
/// ## Implementation Notes
/// This `Connection` struct handles the transport layer (frame I/O) but does not
/// track session state. Higher-level client code must manage the protocol state
/// machine and ensure PDUs are sent in the correct sequence per specification.
///
/// ## References  
/// - SMPP v3.4 Specification Section 2.1 (Session States)
/// - SMPP v3.4 Specification Section 2.1.1 (Session State Diagram)
/// - SMPP v3.4 Specification Section 2.2 (Protocol Data Units)
#[derive(Debug)]
pub struct Connection {
    // The `TcpStream`. It is decorated with a `BufWriter`, which provides write
    // level buffering. The `BufWriter` implementation provided by Tokio is
    // sufficient for our needs.
    stream: BufWriter<TcpStream>,

    // The buffer for reading frames.
    buffer: BytesMut,
}

impl Connection {
    /// Create a new `Connection`, backed by `socket`. Read and write buffers
    /// are initialized.
    pub fn new(socket: TcpStream) -> Connection {
        Connection {
            stream: BufWriter::new(socket),
            // Default to a 4KB read buffer. For the use case of mini redis,
            // this is fine. However, real applications will want to tune this
            // value to their specific use case. There is a high likelihood that
            // a larger read buffer will work better.
            buffer: BytesMut::with_capacity(4 * 1024),
        }
    }

    /// Read a single `Frame` value from the underlying stream.
    ///
    /// The function waits until it has retrieved enough data to parse a frame.
    /// Any data remaining in the read buffer after the frame has been parsed is
    /// kept there for the next call to `read_frame`.
    ///
    /// # Returns
    ///
    /// On success, the received frame is returned. If the `TcpStream`
    /// is closed in a way that doesn't break a frame in half, it returns
    /// `None`. Otherwise, an error is returned.
    pub async fn read_frame(&mut self) -> crate::Result<Option<Frame>> {
        loop {
            // Attempt to parse a frame from the buffered data. If enough data
            // has been buffered, the frame is returned.
            if let Some(frame) = self.parse_frame()? {
                return Ok(Some(frame));
            }

            // There is not enough buffered data to read a frame. Attempt to
            // read more data from the socket.
            //
            // On success, the number of bytes is returned. `0` indicates "end
            // of stream".
            if 0 == self.stream.read_buf(&mut self.buffer).await? {
                // The remote closed the connection. For this to be a clean
                // shutdown, there should be no data in the read buffer. If
                // there is, this means that the peer closed the socket while
                // sending a frame.
                return self
                    .buffer
                    .is_empty()
                    .then(|| None)
                    .ok_or_else(|| "connection reset by peer".into());
            }
        }
    }

    /// Tries to parse a frame from the buffer. If the buffer contains enough
    /// data, the frame is returned and the data removed from the buffer. If not
    /// enough data has been buffered yet, `Ok(None)` is returned. If the
    /// buffered data does not represent a valid frame, `Err` is returned.
    fn parse_frame(&mut self) -> crate::Result<Option<Frame>> {
        use frame::Error::Incomplete;

        // Cursor is used to track the "current" location in the
        // buffer. Cursor also implements `Buf` from the `bytes` crate
        // which provides a number of helpful utilities for working
        // with bytes.
        let mut buf = Cursor::new(&self.buffer[..]);

        // The first step is to check if enough data has been buffered to parse
        // a single frame. This step is usually much faster than doing a full
        // parse of the frame, and allows us to skip allocating data structures
        // to hold the frame data unless we know the full frame has been
        // received.
        match Frame::check(&mut buf) {
            Ok(_) => {
                // Get the complete frame length
                let _len = buf.position() as usize;
                buf.set_position(0);

                // Read the header to get command_length
                let header_buf = &self.buffer[..16];
                let command_length = u32::from_be_bytes([
                    header_buf[0],
                    header_buf[1],
                    header_buf[2],
                    header_buf[3],
                ]);
                let len = command_length as usize;
                // Reset the position to zero before passing the cursor to
                // `Frame::parse`.
                buf.set_position(0);

                // Parse the frame from the buffer. This allocates the necessary
                // structures to represent the frame and returns the frame
                // value.
                //
                // If the encoded frame representation is invalid, an error is
                // returned. This should terminate the **current** connection
                // but should not impact any other connected client.
                let frame = Frame::parse(&mut buf)?;

                // Discard the parsed data from the read buffer.
                //
                // When `advance` is called on the read buffer, all of the data
                // up to `len` is discarded. The details of how this works is
                // left to `BytesMut`. This is often done by moving an internal
                // cursor, but it may be done by reallocating and copying data.
                self.buffer.advance(len);

                // Return the parsed frame to the caller.
                Ok(Some(frame))
            }
            // There is not enough data present in the read buffer to parse a
            // single frame. We must wait for more data to be received from the
            // socket. Reading from the socket will be done in the statement
            // after this `match`.
            //
            // We do not want to return `Err` from here as this "error" is an
            // expected runtime condition.
            Err(Incomplete) => Ok(None),
            // An error was encountered while parsing the frame. The connection
            // is now in an invalid state. Returning `Err` from here will result
            // in the connection being closed.
            Err(e) => Err(e.into()),
        }
    }

    /// Write a single `Frame` value to the underlying stream.
    ///
    /// The `Frame` value is written to the socket using the various `write_*`
    /// functions provided by `AsyncWrite`. Calling these functions directly on
    /// a `TcpStream` is **not** advised, as this will result in a large number of
    /// syscalls. However, it is fine to call these functions on a *buffered*
    /// write stream. The data will be written to the buffer. Once the buffer is
    /// full, it is flushed to the underlying socket.
    pub async fn write_frame(&mut self, frame: &Frame) -> io::Result<()> {
        match frame {
            Frame::BindTransmitter(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::EnquireLink(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::EnquireLinkResp(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::SubmitSm(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::SubmitSmResp(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::QuerySm(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::QuerySmResp(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::ReplaceSm(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::ReplaceSmResp(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::CancelSm(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::CancelSmResp(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::Unbind(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::UnbindResp(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::Outbind(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::GenericNack(pdu) => {
                self.stream.write_all(&pdu.to_bytes()).await?;
            }
            Frame::Unknown { .. } => {
                // For unknown frames, we can't serialize them back
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Cannot write unknown frame type",
                ));
            }
        }

        // Ensure the encoded frame is written to the socket. The calls above
        // are to the buffered stream and writes. Calling `flush` writes the
        // remaining contents of the buffer to the socket.
        self.stream.flush().await
    }
}
