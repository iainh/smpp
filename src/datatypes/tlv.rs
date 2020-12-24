use crate::datatypes::ToBytes;
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Clone, Debug, PartialEq)]
pub struct Tlv {
    pub tag: String,
    pub length: u32,
    pub value: Bytes,
}

impl ToBytes for Tlv {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(1024);

        buffer.put(self.tag.as_bytes());
        buffer.put_u8(b'\0');
        buffer.put_u32(self.length);
        buffer.extend_from_slice(self.value.chunk());

        let mut buf = vec![];
        buf.extend_from_slice(buffer.chunk());

        buf
    }
}
