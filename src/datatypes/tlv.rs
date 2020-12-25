use crate::datatypes::ToBytes;
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Clone, Debug, PartialEq)]
pub struct Tlv {
    /// The Tag field is used to uniquely identify the particular optional parameter in question.
    pub tag: u16,

    /// The Length field indicates the length of the Value field in octets.
    /// Note that this length does not include the length of the Tag and Length fields.
    pub length: u16,

    /// The Value field contains the actual data for the optional parameter in question.
    pub value: Bytes,
}

impl ToBytes for Tlv {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(1024);

        buffer.put_u16(self.tag);
        buffer.put_u16(self.length);
        buffer.extend_from_slice(self.value.chunk());

        let mut buf = vec![];
        buf.extend_from_slice(buffer.chunk());

        buf
    }
}
