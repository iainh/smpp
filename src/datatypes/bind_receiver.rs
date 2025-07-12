use crate::datatypes::interface_version::InterfaceVersion;
use crate::datatypes::numeric_plan_indicator::NumericPlanIndicator;
use crate::datatypes::tlv::Tlv;
use crate::datatypes::{
    AddressRange, CommandId, CommandStatus, Password, SystemId, SystemType, ToBytes, TypeOfNumber,
};
use bytes::{BufMut, Bytes, BytesMut};

/// BindReceiver is used to bind a receiver ESME to the SMSC.
#[derive(Clone, Debug, PartialEq)]
pub struct BindReceiver {
    // pub command_length: u32,
    // pub command_id: CommandId::BindReceiver,
    pub command_status: CommandStatus,
    pub sequence_number: u32,

    // Body
    /// 5.2.1 system_id: This is the identification of the ESME requesting to
    ///       bind as a receiver with the SMSC. It is a fixed length
    ///       alphanumeric field of up to 16 characters. The value may be left
    ///       justified, with trailing blanks (i.e. "abc " is valid). The
    ///       system_id may be used as a destination address for Mobile
    ///       Terminated messages originated by this ESME. The system_id may
    ///       also be used as an originating address for Mobile Originated
    ///        messages sent to this ESME.
    pub system_id: SystemId,

    /// 5.2.2 password: This is the password for authentication. It is a fixed
    ///       length string of 9 characters. If fewer than 9 characters are
    ///       supplied, it must be null padded. If no password is required by
    ///       the SMSC, a NULL (i.e. zero) password should be supplied.
    pub password: Option<Password>,

    /// 5.2.3 system_type: This is used to categorize the type of ESME that is
    ///       binding to the SMSC. Examples include "VMS" (voice mail system)
    ///       and "OTA" (over-the-air activation system). (See section 5.2.7
    ///       for a list of suggested values.) The system_type is specified as
    ///       a fixed length alphanumeric field of up to 13 characters.
    pub system_type: SystemType,

    /// 5.2.4 interface_version: Interface version level supported by the SMSC.
    pub interface_version: InterfaceVersion,

    /// 5.2.5 addr_ton: Type of Number format of the ESME address(es) served
    ///       via this SMPP.
    pub addr_ton: TypeOfNumber,

    /// 5.2.6 addr_npi: Numbering Plan Indicator of the ESME address(es) served
    ///       via this SMPP.
    pub addr_npi: NumericPlanIndicator,

    /// 5.2.7 address_range: This is used to specify a range of SME addresses
    ///       serviced by the ESME. A single address may also be specified.
    pub address_range: AddressRange,
}

#[derive(Debug, thiserror::Error)]
pub enum BindReceiverValidationError {
    #[error("Fixed array fields are always valid - this error should not occur")]
    FixedArrayError,
}

impl BindReceiver {
    /// Validates the BindReceiver PDU according to SMPP v3.4 specification
    /// Fixed array fields are always valid by construction
    pub fn validate(&self) -> Result<(), BindReceiverValidationError> {
        // Fixed-size arrays guarantee field length constraints are met
        Ok(())
    }

    /// Creates a builder for constructing BindReceiver PDUs with validation
    pub fn builder() -> BindReceiverBuilder {
        BindReceiverBuilder::new()
    }
}

/// Builder for creating BindReceiver PDUs with validation and sensible defaults
pub struct BindReceiverBuilder {
    command_status: CommandStatus,
    sequence_number: u32,
    system_id: SystemId,
    password: Option<Password>,
    system_type: SystemType,
    interface_version: InterfaceVersion,
    addr_ton: TypeOfNumber,
    addr_npi: NumericPlanIndicator,
    address_range: AddressRange,
}

impl Default for BindReceiverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BindReceiverBuilder {
    pub fn new() -> Self {
        Self {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            system_id: SystemId::default(),
            password: None,
            system_type: SystemType::default(),
            interface_version: InterfaceVersion::SmppV34,
            addr_ton: TypeOfNumber::Unknown,
            addr_npi: NumericPlanIndicator::Unknown,
            address_range: AddressRange::default(),
        }
    }

    pub fn sequence_number(mut self, seq: u32) -> Self {
        self.sequence_number = seq;
        self
    }

    pub fn system_id(mut self, system_id: &str) -> Self {
        self.system_id = SystemId::from(system_id);
        self
    }

    pub fn password(mut self, password: &str) -> Self {
        self.password = Some(Password::from(password));
        self
    }

    pub fn system_type(mut self, system_type: &str) -> Self {
        self.system_type = SystemType::from(system_type);
        self
    }

    pub fn interface_version(mut self, version: InterfaceVersion) -> Self {
        self.interface_version = version;
        self
    }

    pub fn addr_ton(mut self, ton: TypeOfNumber) -> Self {
        self.addr_ton = ton;
        self
    }

    pub fn addr_npi(mut self, npi: NumericPlanIndicator) -> Self {
        self.addr_npi = npi;
        self
    }

    pub fn address_range(mut self, range: &str) -> Self {
        self.address_range = AddressRange::from(range);
        self
    }

    /// Build the BindReceiver, performing validation
    pub fn build(self) -> Result<BindReceiver, BindReceiverValidationError> {
        let bind_receiver = BindReceiver {
            command_status: self.command_status,
            sequence_number: self.sequence_number,
            system_id: self.system_id,
            password: self.password,
            system_type: self.system_type,
            interface_version: self.interface_version,
            addr_ton: self.addr_ton,
            addr_npi: self.addr_npi,
            address_range: self.address_range,
        };

        // Validate before returning
        bind_receiver.validate()?;
        Ok(bind_receiver)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BindReceiverResponse {
    // pub command_length: u32,
    // pub command_id: CommandId,
    pub command_status: CommandStatus,
    pub sequence_number: u32,
    // body
    pub system_id: SystemId,
    pub sc_interface_version: Option<Tlv>,
}

impl ToBytes for BindReceiver {
    fn to_bytes(&self) -> Bytes {
        // Fixed arrays are always valid by construction
        self.validate().expect("BindReceiver validation failed");

        let system_id = self.system_id.as_ref();
        let password = self.password.as_ref().map(std::convert::AsRef::as_ref);
        let system_type = self.system_type.as_ref();
        let address_range = self.address_range.as_ref();

        let length = 23
            + system_id.len()
            + password.map_or(0, <[u8]>::len)
            + system_type.len()
            + address_range.len();

        let mut buffer = BytesMut::with_capacity(length);
        buffer.put_u32(length as u32);

        buffer.put_u32(CommandId::BindReceiver as u32);
        buffer.put_u32(0u32); // Request PDUs must have command_status = 0 per SMPP spec
        buffer.put_u32(self.sequence_number);

        buffer.put(system_id);
        buffer.put_u8(b'\0');

        if let Some(password) = password {
            buffer.put(password);
        }

        buffer.put_u8(b'\0');

        buffer.put(system_type);
        buffer.put_u8(b'\0');

        buffer.put_u8(self.interface_version as u8);
        buffer.put_u8(self.addr_ton as u8);
        buffer.put_u8(self.addr_npi as u8);

        buffer.put(address_range);
        buffer.put_u8(b'\0');

        buffer.freeze()
    }
}

impl ToBytes for BindReceiverResponse {
    fn to_bytes(&self) -> Bytes {
        // Fixed arrays are always valid by construction
        let system_id = self.system_id.as_ref();

        // Calculate length: header (16) + system_id + null terminator + optional TLV
        let mut length = 16 + system_id.len() + 1;
        if let Some(ref tlv) = self.sc_interface_version {
            length += tlv.to_bytes().len();
        }

        let mut buffer = BytesMut::with_capacity(length);

        // Header
        buffer.put_u32(length as u32);
        buffer.put_u32(CommandId::BindReceiverResp as u32);
        buffer.put_u32(self.command_status as u32);
        buffer.put_u32(self.sequence_number);

        // Body: system_id (mandatory field)
        buffer.put(system_id);
        buffer.put_u8(b'\0'); // null terminator

        // Optional TLV parameters
        if let Some(sc_interface_version) = &self.sc_interface_version {
            buffer.extend_from_slice(&sc_interface_version.to_bytes());
        }

        buffer.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_receiver_to_bytes() {
        let bind_receiver = BindReceiver {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            system_id: SystemId::from("SMPP3TEST"),
            password: Some(Password::from("secret08")),
            system_type: SystemType::from("SUBMIT1"),
            interface_version: InterfaceVersion::SmppV34,
            addr_ton: TypeOfNumber::International,
            addr_npi: NumericPlanIndicator::Isdn,
            address_range: AddressRange::from(""),
        };

        let br_bytes = bind_receiver.to_bytes();

        // Expected byte representation of a bind receiver
        let expected: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x2F, // command_length
            0x00, 0x00, 0x00, 0x01, // command_id (BindReceiver)
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body:
            0x53, 0x4D, 0x50, 0x50, 0x33, 0x54, 0x45, 0x53, 0x54, 0x00, // system_id
            0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x30, 0x38, 0x00, // password
            0x53, 0x55, 0x42, 0x4D, 0x49, 0x54, 0x31, 0x00, // system_type
            0x34, // interface_version
            0x01, // addr_ton
            0x01, // addr_npi
            0x00, // address_range
        ];

        assert_eq!(&br_bytes, &expected);
    }

    #[test]
    fn bind_receiver_validation() {
        // With fixed arrays, the string length is validated at construction time
        let result = std::panic::catch_unwind(|| {
            SystemId::from("A".repeat(16).as_str()) // Too long - max is 15
        });
        assert!(result.is_err()); // Should panic on creation
    }

    #[test]
    fn bind_receiver_builder_basic() {
        let bind_receiver = BindReceiver::builder()
            .system_id("TEST")
            .password("secret")
            .system_type("VMS")
            .address_range("1234")
            .build()
            .unwrap();

        assert_eq!(bind_receiver.system_id.as_str().unwrap(), "TEST");
        assert_eq!(
            bind_receiver.password.as_ref().map(|p| p.as_str().unwrap()),
            Some("secret")
        );
        assert_eq!(bind_receiver.system_type.as_str().unwrap(), "VMS");
        assert_eq!(bind_receiver.address_range.as_str().unwrap(), "1234");
        assert_eq!(bind_receiver.interface_version, InterfaceVersion::SmppV34);
    }

    #[test]
    fn bind_receiver_response_to_bytes() {
        let bind_receiver_response = BindReceiverResponse {
            command_status: CommandStatus::Ok,
            sequence_number: 1,
            system_id: SystemId::from("SMPP3TEST"),
            sc_interface_version: None,
        };

        let brr_bytes = bind_receiver_response.to_bytes();

        // Expected byte representation of a bind receiver response without TLV
        let expected: Vec<u8> = vec![
            // Header:
            0x00, 0x00, 0x00, 0x1A, // command_length (26 bytes total)
            0x80, 0x00, 0x00, 0x01, // command_id (BindReceiverResp = 0x80000001)
            0x00, 0x00, 0x00, 0x00, // command_status
            0x00, 0x00, 0x00, 0x01, // sequence_number
            // Body:
            0x53, 0x4D, 0x50, 0x50, 0x33, 0x54, 0x45, 0x53, 0x54,
            0x00, // system_id "SMPP3TEST\0"
        ];

        assert_eq!(&brr_bytes, &expected);
    }
}
