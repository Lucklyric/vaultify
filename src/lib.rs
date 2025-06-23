//! vault-cli: A secure password manager with hierarchical organization.

pub mod cli;
pub mod crypto;
pub mod error;
pub mod interactive;
pub mod models;
pub mod parser;
pub mod security;
pub mod service;
pub mod utils;

// Re-export commonly used types
pub use error::{Result, VaultError};
pub use models::{Session, VaultDocument, VaultEntry};
pub use service::VaultService;
