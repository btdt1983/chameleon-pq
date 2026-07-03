//! Wire-frame voor het DATApad (blijft onder de MTU).
//!
//! DPI-overwegingen: er is BEWUST geen vaste magic-waarde en geen apart
//! lengteveld meer. Een constante magic op offset 0 van elk pakket is een
//! triviaal matchbaar fingerprint; die is verwijderd. De UDP-datagramgrootte
//! levert de payload-lengte, dus een eigen lengteveld is overbodig. De
//! resterende headervelden (type, session_id, sequence) zijn nodig om de
//! sessie/sleutel en de nonce-counter te kiezen — net als WireGuard houden we
//! die zichtbaar — maar voor Data-frames worden ze als AEAD associated data
//! meegeauthenticeerd (zie session.rs), zodat knoeien met de header de
//! tag-verificatie breekt.
//!
//! EERLIJKE GRENS: dit verkleint de vingerafdruk (geen statische magic, header
//! geauthenticeerd), maar het is GEEN volledige verkeersanalyse-weerstand —
//! het type-byte en de timing/grootte-patronen blijven zichtbaar. Volledige
//! obfuscatie (obfs4-/Shadowsocks-stijl) is toekomstig werk.

use crate::error::{ChameleonError, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const HEADER_LEN: usize = 13; // type(1) + session_id(4) + sequence(8)
pub const MAX_PAYLOAD: usize = 1280 - HEADER_LEN; // MTU-veilig datapad

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x01,
    Handshake = 0x02,
    KeepAlive = 0x03,
    Close = 0x04,
    /// Cover/dummy-verkeer (Fase 3): een inner-type dat de ontvanger stil
    /// weggooit. Gebruikt door de constant-rate pacer om lege slots te vullen,
    /// zodat burst- en idle-patronen verdwijnen. Zit alleen in de INNER framing
    /// (obf.rs), nooit als zichtbaar wire-byte.
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
        if plen > MAX_PAYLOAD.max(u16::MAX as usize) {
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
        // Geen apart lengteveld: het UDP-datagram levert de grens, dus de
        // rest van de buffer is de payload.
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
        // Onbekend type blijft een fout (fail-closed).
        assert!(FrameType::from_u8(0x06).is_err());
    }
}
