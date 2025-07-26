// Simplified Connection implementation using the new codec architecture
//
// This shows how much cleaner the connection layer becomes when the
// codec logic is properly separated.

use crate::codec::{CodecError, Encodable, Frame, PduHeader, PduRegistry};
use bytes::{Buf, BytesMut};
use std::io::{self, Cursor};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;

/// SMPP v3.4 Connection with separated codec
#[derive(Debug)]
pub struct Connection {
    /// Buffered TCP stream for efficient I/O
    stream: BufWriter<TcpStream>,
    
    /// Read buffer for incoming data
    buffer: BytesMut,
    
    /// PDU registry for decoding
    registry: PduRegistry,
}

impl Connection {
    /// Create a new connection with default PDU registry
    pub fn new(socket: TcpStream) -> Self {
        Self {
            stream: BufWriter::new(socket),
            buffer: BytesMut::with_capacity(4 * 1024),
            registry: PduRegistry::new(),
        }
    }

    /// Read a single frame from the connection
    ///
    /// Returns None if the connection is closed cleanly
    pub async fn read_frame(&mut self) -> Result<Option<Frame>, ConnectionError> {
        loop {
            // Try to parse a frame from buffered data
            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }

            // Read more data into buffer
            if 0 == self.stream.read_buf(&mut self.buffer).await? {
                // Connection closed
                return if self.buffer.is_empty() {
                    Ok(None) // Clean shutdown
                } else {
                    Err(ConnectionError::IncompleteFrame)
                };
            }
        }
    }

    /// Try to parse a frame from the current buffer
    fn try_parse_frame(&mut self) -> Result<Option<Frame>, ConnectionError> {
        let mut buf = Cursor::new(&self.buffer[..]);

        // Check if we have enough data for a header
        if buf.remaining() < PduHeader::SIZE {
            return Ok(None);
        }

        // Parse header to get PDU length
        let header = PduHeader::decode(&mut buf)?;

        // Check if we have the complete PDU
        let body_size = header.command_length as usize - PduHeader::SIZE;
        if buf.remaining() < body_size {
            return Ok(None); // Need more data
        }

        // Reset cursor to start of PDU
        buf.set_position(0);

        // Parse header again (we know it's valid now)
        let header = PduHeader::decode(&mut buf)?;

        // Decode the PDU body using registry
        let frame = self.registry.decode_pdu(header, &mut buf)?;

        // Remove parsed data from buffer
        self.buffer.advance(header.command_length as usize);

        Ok(Some(frame))
    }

    /// Write a PDU to the connection
    ///
    /// This is much simpler than the old match-based approach
    pub async fn write_pdu<T: Encodable>(&mut self, pdu: &T) -> Result<(), ConnectionError> {
        let mut buf = BytesMut::with_capacity(pdu.encoded_size());
        pdu.encode(&mut buf)?;
        
        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;
        
        Ok(())
    }

    /// Write a frame (if you need to work with the Frame enum)
    pub async fn write_frame(&mut self, frame: &Frame) -> Result<(), ConnectionError> {
        match frame {
            Frame::BindTransmitter(pdu) => self.write_pdu(pdu).await,
            Frame::BindReceiver(pdu) => self.write_pdu(pdu).await,
            Frame::BindTransceiver(pdu) => self.write_pdu(pdu).await,
            Frame::SubmitSm(pdu) => self.write_pdu(pdu.as_ref()).await,
            Frame::EnquireLink(pdu) => self.write_pdu(pdu).await,
            Frame::Unbind(pdu) => self.write_pdu(pdu).await,
            Frame::BindTransmitterResp(pdu) => self.write_pdu(pdu).await,
            Frame::BindReceiverResp(pdu) => self.write_pdu(pdu).await,
            Frame::BindTransceiverResp(pdu) => self.write_pdu(pdu).await,
            Frame::SubmitSmResp(pdu) => self.write_pdu(pdu).await,
            Frame::DeliverSm(pdu) => self.write_pdu(pdu.as_ref()).await,
            Frame::DeliverSmResp(pdu) => self.write_pdu(pdu).await,
            Frame::EnquireLinkResp(pdu) => self.write_pdu(pdu).await,
            Frame::UnbindResp(pdu) => self.write_pdu(pdu).await,
            Frame::GenericNack(pdu) => self.write_pdu(pdu).await,
            Frame::Outbind(pdu) => self.write_pdu(pdu).await,
            Frame::Unknown { header, body } => {
                // For unknown frames, reconstruct the raw PDU
                let mut buf = BytesMut::with_capacity(header.command_length as usize);
                header.encode(&mut buf);
                buf.extend_from_slice(body);
                self.stream.write_all(&buf).await?;
                self.stream.flush().await?;
                Ok(())
            }
        }
    }

    /// Split the connection into read and write halves for concurrent use
    pub fn split(self) -> (ConnectionReader, ConnectionWriter) {
        // This is a simplified version - real implementation would need
        // to properly split the TcpStream using tokio's split() method
        todo!("Implement connection splitting")
    }

    /// Get the registry for registering custom PDU types
    pub fn registry_mut(&mut self) -> &mut PduRegistry {
        &mut self.registry
    }
}

/// Read half of a split connection
pub struct ConnectionReader {
    // Implementation details would go here
}

/// Write half of a split connection  
pub struct ConnectionWriter {
    // Implementation details would go here
}

/// Connection-level errors
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("Codec error: {0}")]
    Codec(#[from] CodecError),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Connection closed with incomplete frame")]
    IncompleteFrame,

    #[error("Connection closed")]
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::enquire_link::{EnquireLink, EnquireLinkResponse};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn test_connection_roundtrip() {
        // Create in-memory connection for testing
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let mut conn = Connection::new(stream);

            // Send enquire_link
            let enquire = EnquireLink::new(42);
            conn.write_pdu(&enquire).await.unwrap();

            // Read response
            if let Some(Frame::EnquireLinkResp(resp)) = conn.read_frame().await.unwrap() {
                assert_eq!(resp.sequence_number, 42);
            } else {
                panic!("Expected EnquireLinkResponse");
            }
        });

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = Connection::new(stream);

            // Read enquire_link
            if let Some(Frame::EnquireLink(req)) = conn.read_frame().await.unwrap() {
                // Send response
                let resp = EnquireLinkResponse::new(req.sequence_number);
                conn.write_pdu(&resp).await.unwrap();
            } else {
                panic!("Expected EnquireLink");
            }
        });

        // Wait for both sides to complete
        tokio::try_join!(client_task, server_task).unwrap();
    }
}
