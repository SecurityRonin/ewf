use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EwfError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid EWF signature")]
    InvalidSignature,

    #[error("buffer too short: expected {expected}, got {got}")]
    BufferTooShort { expected: usize, got: usize },

    #[error("invalid chunk size: {0}")]
    InvalidChunkSize(u32),

    #[error("missing volume section")]
    MissingVolume,

    #[error("decompression error: {0}")]
    Decompression(String),

    #[error("segment gap: expected segment {expected}, got {got}")]
    SegmentGap { expected: u32, got: u32 },

    #[error("no segment files found matching: {0}")]
    NoSegments(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("encrypted EWF2 images are not supported")]
    EncryptedNotSupported,
}

pub type Result<T> = std::result::Result<T, EwfError>;
