pub mod cfg_val;
mod packets;
mod types;

use crate::error::MemWriterError;
use crate::parser::UbxChecksumCalc;
pub use packets::*;
pub use types::*;

/// Information about concrete UBX protocol's packet
pub trait UbxPacketMeta {
    const CLASS: u8;
    const ID: u8;
    const FIXED_PAYLOAD_LEN: Option<u16>;
    const MAX_PAYLOAD_LEN: u16;
}

pub(crate) const SYNC_CHAR_1: u8 = 0xb5;
pub(crate) const SYNC_CHAR_2: u8 = 0x62;

/// Abstraction for buffer creation/reallocation
/// to storing packet
pub trait MemWriter {
    type Error;
    /// make sure that we have at least `len` bytes for writing
    fn reserve_allocate(&mut self, len: usize) -> Result<(), MemWriterError<Self::Error>>;
    fn write(&mut self, buf: &[u8]) -> Result<(), MemWriterError<Self::Error>>;
}

#[cfg(feature = "std")]
impl MemWriter for Vec<u8> {
    type Error = std::io::Error;

    fn reserve_allocate(&mut self, len: usize) -> Result<(), MemWriterError<Self::Error>> {
        self.reserve(len);
        Ok(())
    }
    fn write(&mut self, buf: &[u8]) -> Result<(), MemWriterError<Self::Error>> {
        let ret = <dyn std::io::Write>::write(self, buf).map_err(MemWriterError::Custom)?;
        if ret == buf.len() {
            Ok(())
        } else {
            Err(MemWriterError::NotEnoughMem)
        }
    }
}

pub trait UbxPacketCreator {
    /// Create packet and store bytes sequence to somewhere using `out`
    fn create_packet<T: MemWriter>(self, out: &mut T) -> Result<(), MemWriterError<T::Error>>;
}

/// Packet not supported yet by this crate
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct UbxUnknownPacketRef<'a> {
    pub payload: &'a [u8],
    pub class: u8,
    pub msg_id: u8,
}

/// Request specific packet
pub struct UbxPacketRequest {
    req_class: u8,
    req_id: u8,
}

impl UbxPacketRequest {
    pub const PACKET_LEN: usize = 8;

    #[inline]
    pub fn request_for<T: UbxPacketMeta>() -> Self {
        Self {
            req_class: T::CLASS,
            req_id: T::ID,
        }
    }
    #[inline]
    pub fn request_for_unknown(req_class: u8, req_id: u8) -> Self {
        Self { req_class, req_id }
    }

    #[inline]
    pub fn into_packet_bytes(self) -> [u8; Self::PACKET_LEN] {
        let mut ret = [
            SYNC_CHAR_1,
            SYNC_CHAR_2,
            self.req_class,
            self.req_id,
            0,
            0,
            0,
            0,
        ];
        let mut checksum_calc = UbxChecksumCalc::new();
        checksum_calc.update(&ret[2..6]);
        let checksum = checksum_calc.result();
        [ret[6], ret[7]] = checksum.to_le_bytes();
        ret
    }
}
