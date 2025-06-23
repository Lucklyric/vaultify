//! Error types for vault-cli.

use std::path::PathBuf;
use thiserror::Error;

/// Main error type for vault operations.
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault file not found: {0}")]
    VaultNotFound(PathBuf),

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Entry already exists: {0}")]
    EntryExists(String),

    #[error("Invalid scope name: {0}")]
    InvalidScope(String),

    #[error("No encrypted content in entry: {0}")]
    NoEncryptedContent(String),

    #[error("No salt found for entry: {0}")]
    NoSalt(String),

    #[error("Decryption failed - incorrect password")]
    DecryptionFailed,

    #[error("Passwords do not match")]
    PasswordMismatch,

    #[error("No secret provided")]
    NoSecret,

    #[error("Operation cancelled by user")]
    Cancelled,

    #[error("Session expired")]
    SessionExpired,

    #[error("Clipboard operation failed")]
    ClipboardFailed,

    #[error("Editor launch failed")]
    EditorFailed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(#[from] crate::parser::ParseError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error("Permission error: {0}")]
    Permission(String),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;
