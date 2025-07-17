//! vaultify: A secure password manager with hierarchical organization.

pub mod cli;
pub mod crypto;
pub mod error;
pub mod gpg;
pub mod interactive;
pub mod models;
pub mod operations;
pub mod secure_temp;
pub mod security;
pub mod service;
pub mod toml_parser;
pub mod utils;

// Re-export commonly used types
pub use error::{Result, VaultError};
pub use models::{VaultDocument, VaultEntry};
pub use service::VaultService;
