use thiserror::Error;

/// Central error hierarchy for the whole system.
#[derive(Debug, Error)]
pub enum ChameleonError {
    #[error("UDP / IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Packet too short: got {got}, need {need}")]
    PacketTooShort { got: usize, need: usize },

    #[error("Unknown frame type byte: {0:#04x}")]
    UnknownFrameType(u8),

    #[error("Payload exceeds maximum size {0}")]
    PayloadTooLarge(usize),

    #[error("Handshake error in state '{state}': {msg}")]
    Handshake { state: String, msg: String },

    #[error("Decryption failed (tag mismatch, replay, or corrupt data)")]
    DecryptionFailed,

    #[error("Key derivation failed: {0}")]
    Kdf(String),

    #[error("Channel closed (receiver dropped)")]
    ChannelClosed,

    #[error("Rekey required: nonce counter exhausted")]
    RekeyRequired,

    #[error("Route error: {0}")]
    Route(String),

    #[error("Kill switch error: {0}")]
    KillSwitch(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ChameleonError>;
