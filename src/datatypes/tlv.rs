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
    fn to_bytes(&self) -> Bytes {
        // the required size of the buffer if the length of the value plus 4 octets for the two u16s
        let mut buffer = BytesMut::with_capacity(self.value.len() + 4);

        buffer.put_u16(self.tag);
        buffer.put_u16(self.length);
        buffer.put(self.value.chunk());

        buffer.freeze()
    }
}
