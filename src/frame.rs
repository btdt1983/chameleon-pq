//! Wire-frame for the DATA path (stays below the MTU).
//!
//! DPI considerations: there is DELIBERATELY no fixed magic-value and no
//! separate length-field anymore. A constant magic at offset 0 of every packet
//! is a trivially matchable fingerprint; it has been removed. The UDP-datagram
//! size provides the payload-length, so a dedicated length-field is redundant.
//! The remaining header-fields (type, session_id, sequence) are needed to
//! choose the session/key and the nonce-counter — like WireGuard we keep those
//! visible — but for Data-frames they are authenticated as AEAD associated data
//! (see session.rs), so tampering with the header breaks the tag-verification.
//!
//! HONEST LIMIT: this shrinks the fingerprint (no static magic, header
//! authenticated), but it is NOT full traffic-analysis resistance — the
//! type-byte and the timing/size-patterns stay visible. Full obfuscation
//! (obfs4-/Shadowsocks-style) is future work.

use crate::error::{ChameleonError, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const HEADER_LEN: usize = 13; // type(1) + session_id(4) + sequence(8)
pub const MAX_PAYLOAD: usize = 1280 - HEADER_LEN; // MTU-safe data path

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x01,
    Handshake = 0x02,
    KeepAlive = 0x03,
    Close = 0x04,
    /// Cover/dummy-traffic (Phase 3): an inner-type that the receiver silently
    /// discards. Used by the constant-rate pacer to fill empty slots, so that
    /// burst- and idle-patterns disappear. Sits only in the INNER framing
    /// (obf.rs), never as a visible wire-byte.
    Padding = 0x05,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Handshake),
            0x03 => Ok(Self::KeepAlive),
            0x04 => Ok(Self::Close),
            0x05 => Ok(Self::Padding),
            _ => Err(ChameleonError::UnknownFrameType(v)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub session_id: u32,
    pub sequence: u64,
    pub payload: Bytes,
}

impl Frame {
    pub fn new_data(session_id: u32, sequence: u64, payload: Bytes) -> Self {
        Self {
            frame_type: FrameType::Data,
            session_id,
            sequence,
            payload,
        }
    }

    pub fn new_handshake(payload: Bytes) -> Self {
        Self {
            frame_type: FrameType::Handshake,
            session_id: 0,
            sequence: 0,
            payload,
        }
    }

    pub fn encode(&self) -> Result<Bytes> {
        let plen = self.payload.len();
        if plen > MAX_PAYLOAD {
            return Err(ChameleonError::PayloadTooLarge(plen));
        }
        let mut buf = BytesMut::with_capacity(HEADER_LEN + plen);
        buf.put_u8(self.frame_type as u8);
        buf.put_u32_le(self.session_id);
        buf.put_u64_le(self.sequence);
        buf.put_slice(&self.payload);
        Ok(buf.freeze())
    }

    pub fn decode(mut raw: Bytes) -> Result<Self> {
        if raw.len() < HEADER_LEN {
            return Err(ChameleonError::PacketTooShort {
                got: raw.len(),
                need: HEADER_LEN,
            });
        }
        let frame_type = FrameType::from_u8(raw.get_u8())?;
        let session_id = raw.get_u32_le();
        let sequence = raw.get_u64_le();
        // No separate length-field: the UDP-datagram provides the boundary, so
        // the rest of the buffer is the payload.
        let payload = raw.copy_to_bytes(raw.remaining());
        Ok(Self {
            frame_type,
            session_id,
            sequence,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_type_from_u8_covers_padding() {
        assert_eq!(FrameType::from_u8(0x05).unwrap(), FrameType::Padding);
        assert_eq!(FrameType::Padding as u8, 0x05);
        // Unknown type stays an error (fail-closed).
        assert!(FrameType::from_u8(0x06).is_err());
    }
}
