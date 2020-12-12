//! Provides a type representing an SMPP protocol frame as well as utilities for
//! parsing frames from a byte array.

use crate::datatypes::{BindTransmitter, BindTransmitterResponse, CommandId, CommandStatus};
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
}

#[derive(Debug)]
pub enum Error {
    /// Not enough data is available to parse a message
    Incomplete,

    /// Invalid message encoding
    Other(crate::Error),
}

impl Frame {
    /// Checks if an entire message can be decoded from `src`
    pub fn check(src: &mut Cursor<&[u8]>) -> Result<(), Error> {
        let command_length = peek_u32(src)? as usize;
        if command_length <= src.remaining() {
            // todo: should also verify that the command length is at least the length of the
            //   minimum header size for either this PDU or all PDUs

            Ok(())
        } else {
            Err(Error::Incomplete)
        }
    }

    /// The message has already been validated with `check`.
    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Frame, Error> {
        let command_length = get_u32(src)?;
        dbg!(command_length);

        let command_id = CommandId::try_from(get_u32(src)?).unwrap();
        dbg!(&command_id);

        let command = match command_id {
            CommandId::BindTransmitter => {
                let command_status = CommandStatus::try_from(get_u32(src)?).unwrap();
                let sequence_number = get_u32(src)?;

                let system_id = get_until_coctet_string(src)?;
                let password = get_until_coctet_string(src)?;
                let system_type = get_until_coctet_string(src)?;

                let addr_ton = get_u32(src)?;
                let interface_version = get_u32(src)?;
                let addr_npi = get_u32(src)?;

                let address_range = get_until_coctet_string(src)?;

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
            _ => todo!(),
        };

        dbg!(&command);

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

fn get_until_coctet_string(src: &mut Cursor<&[u8]>) -> Result<String, Error> {
    if !&src.has_remaining() {
        return Err(Error::Incomplete);
    }

    let sp = src.position();
    let terminator_index = src
        .bytes()
        .into_iter()
        .position(|x| x.is_ok() && x.unwrap() == 0u8)
        .ok_or(Error::Incomplete)?;

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
            } // Frame::Simple(response) => response.fmt(fmt),
              // Frame::Error(msg) => write!(fmt, "error: {}", msg),
              // Frame::Integer(num) => num.fmt(fmt),
              // Frame::Bulk(msg) => match str::from_utf8(msg) {
              //     Ok(string) => string.fmt(fmt),
              //     Err(_) => write!(fmt, "{:?}", msg),
              // },
              // Frame::Null => "(nil)".fmt(fmt),
              // Frame::Array(parts) => {
              //     for (i, part) in parts.iter().enumerate() {
              //         if i > 0 {
              //             write!(fmt, " ")?;
              //             part.fmt(fmt)?;
              //         }
              //     }
              //
              //     Ok(())
              // }
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
    use std::convert::TryInto;
    use std::io::Cursor;

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

        let result = get_until_coctet_string(&mut buff);
        assert_eq!(result.is_ok(), true);

        let result = result.unwrap();

        assert_eq!(result.len(), 23);
        assert_eq!("This is the first part\0".to_string(), result);

        // Ensure that the cursor has advanced 4 bytes
        assert_eq!(buff.remaining(), data.len() - 23);

        let result = get_until_coctet_string(&mut buff);
        assert_eq!(result.is_ok(), true);

        let result = result.unwrap();
        assert_eq!("This is the second.\0".to_string(), result);
    }
}
