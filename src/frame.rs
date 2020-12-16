//! Provides a type representing an SMPP protocol frame as well as utilities for
//! parsing frames from a byte array.

use crate::datatypes::{
    BindTransmitter, BindTransmitterResponse, CommandId, CommandStatus, SubmitSm, SubmitSmResponse,
    Unbind, UnbindResponse,
};
use bytes::Buf;
use core::fmt;
use std::convert::TryFrom;
use std::io::{Cursor, Read};
use std::num::TryFromIntError;
use std::string::FromUtf8Error;

#[derive(Clone, Debug)]
pub enum Frame {
    BindTransmitter(BindTransmitter),
    BindTransmitterResponse(BindTransmitterResponse),
    SubmitSm(SubmitSm),
    SubmitSmResponse(SubmitSmResponse),
    Unbind(Unbind),
    UnbindResponse(UnbindResponse),
}

#[derive(Debug)]
pub enum Error {
    /// Not enough data is available to parse a message
    Incomplete,

    /// Invalid message encoding
    Other(crate::Error),
}

impl Frame {
    /// Checks if an entire message can be decoded from `src`. If it can be, return the
    /// command_length that can be used to allocate the buffer for parsing.
    pub fn check(src: &mut Cursor<&[u8]>) -> Result<usize, Error> {
        // The length of the PDU including the command_length.
        let command_length = peek_u32(src)? as usize;

        // PDUs have a the same header structure consisting of the following fields:
        //  - command_length (4 octets)
        //  - command_type (4 octets)
        //  - command_status (4 octets)
        //  - sequence_number (4 octets)
        // for a total of 16 octets
        if command_length <= src.remaining() && command_length > 16 {
            Ok(command_length)
        } else {
            Err(Error::Incomplete)
        }
    }

    /// The message has already been validated with `check`.
    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Frame, Error> {
        // parse the header
        let _command_length = get_u32(src)?;
        let command_id = CommandId::try_from(get_u32(src)?).unwrap();
        let command_status = CommandStatus::try_from(get_u32(src)?).unwrap();
        let sequence_number = get_u32(src)?;

        // Based on the command_id, parse the body
        let command = match command_id {
            CommandId::BindTransmitter => {
                let system_id = get_until_coctet_string(src, Some(16))?;
                let password = get_until_coctet_string(src, Some(9))?;
                let system_type = get_until_coctet_string(src, Some(13))?;
                let addr_ton = get_u8(src)?;

                let interface_version = get_u8(src)?;
                let addr_npi = get_u8(src)?;

                let address_range = get_until_coctet_string(src, Some(41))?;

                let pdu = BindTransmitter {
                    command_status,
                    sequence_number,
                    system_id,
                    password,
                    system_type,
                    interface_version,
                    addr_ton,
                    addr_npi,
                    address_range,
                };
                Frame::BindTransmitter(pdu)
            }
            _ => todo!("Implement the parse function for all the other PDUs"),
        };

        Ok(command)
    }

    /// Converts the frame to an "unexpected frame" error
    pub(crate) fn to_error(&self) -> crate::Error {
        format!("unexpected frame: {}", self).into()
    }
}

/// Peek a u8 from the buffer
fn peek_u8(src: &mut Cursor<&[u8]>) -> Result<u8, Error> {
    if !src.has_remaining() {
        return Err(Error::Incomplete);
    }

    let starting_position = src.position();
    let val = src.get_u8();
    src.set_position(starting_position);

    Ok(val)
}

/// Peek a u32 from the buffer
fn peek_u32(src: &mut Cursor<&[u8]>) -> Result<u32, Error> {
    if src.remaining() < 4 {
        return Err(Error::Incomplete);
    }

    let starting_position = src.position();
    let val = src.get_u32();
    src.set_position(starting_position);

    Ok(val)
}

/// Get a u8 from the buffer
fn get_u8(src: &mut Cursor<&[u8]>) -> Result<u8, Error> {
    if !src.has_remaining() {
        return Err(Error::Incomplete);
    }

    Ok(src.get_u8())
}

/// Get a u32 from the buffer
fn get_u32(src: &mut Cursor<&[u8]>) -> Result<u32, Error> {
    if src.remaining() < 4 {
        return Err(Error::Incomplete);
    }

    Ok(src.get_u32())
}

fn get_until_coctet_string(
    src: &mut Cursor<&[u8]>,
    max_length: Option<u64>,
) -> Result<String, Error> {
    if !&src.has_remaining() {
        return Err(Error::Incomplete);
    }

    let sp = src.position();
    let mut terminator_index = src
        .bytes()
        .into_iter()
        .position(|x| x.is_ok() && x.unwrap() == 0u8)
        .ok_or(Error::Incomplete)?;

    if let Some(max_length) = max_length {
        // Constrain to the max_length of the field if we haven't found a null terminator
        if terminator_index >= (sp + max_length) as usize {
            terminator_index = (sp + max_length) as usize - 1;
        }
    }

    let mut buffer = vec![0; terminator_index + 1];

    src.set_position(sp);
    src.copy_to_slice(&mut *buffer);

    let result = String::from_utf8_lossy(&buffer).to_string();

    Ok(result)
}

/// Advance the cursor by n characters
fn skip(src: &mut Cursor<&[u8]>, n: usize) -> Result<(), Error> {
    if src.remaining() < n {
        return Err(Error::Incomplete);
    }

    src.advance(n);
    Ok(())
}

impl PartialEq<Frame> for Frame {
    fn eq(&self, other: &Frame) -> bool {
        // ???
        false
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        // todo: we can probably do a lot better here...
        match self {
            Frame::BindTransmitter(msg) => {
                write!(fmt, "Bind Transmitter {:?}", msg.command_status)
            }
            Frame::BindTransmitterResponse(msg) => {
                write!(fmt, "Bind Transmitter Response {:?}", msg.command_status)
            }
            Frame::SubmitSm(msg) => {
                write!(fmt, "Submit SM {:?}", msg.command_status)
            }
            Frame::SubmitSmResponse(msg) => {
                write!(fmt, "Submit SM Response {:?}", msg.command_status)
            }
            Frame::Unbind(msg) => {
                write!(fmt, "Unbind {:?}", msg.command_status)
            }
            Frame::UnbindResponse(msg) => {
                write!(fmt, "Unbind Response {:?}", msg.command_status)
            }
        }
    }
}

impl From<String> for Error {
    fn from(src: String) -> Error {
        Error::Other(src.into())
    }
}

impl From<&str> for Error {
    fn from(src: &str) -> Error {
        src.to_string().into()
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_src: FromUtf8Error) -> Error {
        "protocol error; invalid frame format".into()
    }
}

impl From<TryFromIntError> for Error {
    fn from(_src: TryFromIntError) -> Error {
        "protocol error; invalid frame format".into()
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Incomplete => "stream ended early".fmt(fmt),
            Error::Other(err) => err.fmt(fmt),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};
    use std::convert::TryInto;
    use std::io::{Cursor, Write};

    #[test]
    fn peek_u8_test() {
        let mut data: Vec<u8> = vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        let mut buff = Cursor::new(data.as_slice());

        // Before peeking, the remaining bytes should be the same as the total number of elements
        assert_eq!(buff.remaining(), data.len());

        let result = peek_u8(&mut buff);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap(), 10u8);

        // Ensure that we are peeking ant not getting. (cursor position should not have moved)
        assert_eq!(buff.remaining(), data.len());
    }

    #[test]
    fn get_u8_test() {
        let mut data: Vec<u8> = vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        let mut buff = Cursor::new(data.as_slice());

        let result = get_u8(&mut buff);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap(), 10u8);

        // Ensure that the cursor has advanced
        assert_eq!(buff.remaining(), data.len() - 1);
    }

    #[test]
    fn peek_u32_test() {
        let mut data: Vec<u8> = vec![0x1, 0xF, 0xF, 0xF, 6, 5, 4, 3, 2, 1];
        let mut buff = Cursor::new(data.as_slice());

        let result = peek_u32(&mut buff);
        assert_eq!(result.is_ok(), true);
        assert_eq!(
            result.unwrap(),
            u32::from_be_bytes(data[0..4].try_into().unwrap())
        );

        // Ensure that we are peeking and not getting
        assert_eq!(buff.remaining(), data.len());
    }

    #[test]
    fn get_u32_test() {
        let mut data: Vec<u8> = vec![0x1, 0xF, 0xF, 0xF, 6, 5, 4, 3, 2, 1];
        let mut buff = Cursor::new(data.as_slice());

        let result = get_u32(&mut buff);
        assert_eq!(result.is_ok(), true);
        assert_eq!(
            result.unwrap(),
            u32::from_be_bytes(data[0..4].try_into().unwrap())
        );

        // Ensure that the cursor has advanced 4 bytes
        assert_eq!(buff.remaining(), data.len() - 4);
    }

    #[test]
    fn skip_test() {
        use std::io::Cursor;

        let mut data: Vec<u8> = vec![0x1, 0xF, 0xF, 0xF, 6, 5, 4, 3, 2, 1];
        let mut buff = Cursor::new(data.as_slice());

        let result = skip(&mut buff, 4);
        assert_eq!(result.is_ok(), true);

        let result = get_u8(&mut buff);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap(), 6u8);

        let result = skip(&mut buff, 2);
        assert_eq!(result.is_ok(), true);

        let result = get_u8(&mut buff);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap(), 3u8);

        // Ensure that the cursor has advanced 4 + 1 + 2 + 1 = 8 positions
        assert_eq!(buff.remaining(), data.len() - 8);
    }

    #[test]
    fn get_until_coctet_string_test() {
        use std::io::Cursor;

        let mut data = "This is the first part\0This is the second.\0".as_bytes();
        let mut buff = Cursor::new(data);

        let result = get_until_coctet_string(&mut buff, Some(23));
        assert_eq!(result.is_ok(), true);

        let result = result.unwrap();

        assert_eq!(result.len(), 23);
        assert_eq!("This is the first part\0".to_string(), result);

        // Ensure that the cursor has advanced 4 bytes
        assert_eq!(buff.remaining(), data.len() - 23);

        let result = get_until_coctet_string(&mut buff, None);
        assert_eq!(result.is_ok(), true);

        let result = result.unwrap();
        assert_eq!("This is the second.\0".to_string(), result);

        let mut data = "This is the first part\0This is the second.\0".as_bytes();
        let mut buff = Cursor::new(data);

        let result = get_until_coctet_string(&mut buff, Some(4));
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap().len(), 4);
    }

    #[test]
    fn check_test() {
        use std::io::Cursor;

        let mut data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x2F, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x53, 0x4D, 0x50, 0x50, 0x33, 0x54, 0x45, 0x53, 0x54, 0x00, 0x73, 0x65,
            0x63, 0x72, 0x65, 0x74, 0x30, 0x38, 0x00, 0x53, 0x55, 0x42, 0x4D, 0x49, 0x54, 0x31,
            0x00, 0x00, 0x01, 0x01, 0x00,
        ];

        let mut data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::check(&mut buff);
        assert!(result.is_ok());

        // Invalid length: (3F when it should be 2F)
        let mut data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x53, 0x4D, 0x50, 0x50, 0x33, 0x54, 0x45, 0x53, 0x54, 0x00, 0x73, 0x65,
            0x63, 0x72, 0x65, 0x74, 0x30, 0x38, 0x00, 0x53, 0x55, 0x42, 0x4D, 0x49, 0x54, 0x31,
            0x00, 0x00, 0x01, 0x01, 0x00,
        ];

        let mut data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::check(&mut buff);
        assert!(result.is_err());
    }

    #[test]
    fn parse_test() {
        use std::io::Cursor;

        let mut data: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x2F, // command_length
            0x00, 0x00, 0x00, 0x02, // command_id
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body:
            0x53, 0x4D, 0x50, 0x50, 0x33, 0x54, 0x45, 0x53, 0x54, 0x00, // system_id
            0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x30, 0x38, 0x00, // password
            0x53, 0x55, 0x42, 0x4D, 0x49, 0x54, 0x31, 0x00, // system_type
            0x00, // interface_version
            0x01, // addr_tom
            0x01, // addr_npi
            0x00, // address_range
        ];

        let mut data = data.as_slice();
        let mut buff = Cursor::new(data);

        let result = Frame::parse(&mut buff);

        assert!(result.is_ok());

        let frame = result.unwrap();
        if let Frame::BindTransmitter(bt) = frame {
            assert_eq!(bt.command_status, CommandStatus::Ok);
            assert_eq!(&bt.system_id, "SMPP3TEST\0");
        } else {
            assert!(false, "Unexpected frame variant");
        }
    }
}
