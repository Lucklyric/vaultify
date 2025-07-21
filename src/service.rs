//! Service layer for vault operations.

use crate::crypto::VaultCrypto;
use crate::error::{Result, VaultError};
use crate::models::{VaultDocument, VaultEntry};
use crate::toml_parser::TomlParser;
use crate::utils;
use std::collections::HashMap;
use std::path::Path;

/// Service for vault operations.
pub struct VaultService {
    crypto: VaultCrypto,
    parser: TomlParser,
}

impl Default for VaultService {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultService {
    /// Create a new vault service.
    pub fn new() -> Self {
        Self {
            crypto: VaultCrypto::new(),
            parser: TomlParser::new(),
        }
    }

    /// Load a vault document from file.
    pub fn load_vault(&self, path: &Path) -> Result<VaultDocument> {
        // Read file content
        let content = std::fs::read_to_string(path).map_err(VaultError::Io)?;

        // Parse TOML format
        let mut doc = self.parser.parse(&content)?;

        // Set file path
        doc.file_path = Some(path.to_path_buf());
        Ok(doc)
    }

    /// Save a vault document to file.
    pub fn save_vault(&self, doc: &VaultDocument, path: &Path) -> Result<()> {
        // Check if vault already exists
        if path.exists() {
            // Prompt for backup
            if utils::prompt_yes_no("Create backup before saving?", true)? {
                self.create_backup(path)?;
            }
        }

        // Format as TOML and save
        let content = self.parser.format(doc);
        std::fs::write(path, content).map_err(VaultError::Io)?;
        Ok(())
    }

    /// Create a backup of the vault file
    fn create_backup(&self, path: &Path) -> Result<()> {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let file_name = path
            .file_name()
            .ok_or_else(|| VaultError::Other("Invalid file name".to_string()))?
            .to_string_lossy();
        let backup_path = path.with_file_name(format!("{file_name}.backup.{timestamp}"));

        // Check if backup already exists (unlikely with timestamp, but just in case)
        if backup_path.exists()
            && !utils::prompt_yes_no(
                &format!(
                    "Backup {} already exists. Overwrite?",
                    backup_path.display()
                ),
                true,
            )?
        {
            return Err(VaultError::Cancelled);
        }

        std::fs::copy(path, &backup_path).map_err(VaultError::Io)?;
        println!("Created backup: {}", backup_path.display());
        Ok(())
    }

    /// Add a new entry to the vault.
    pub fn add_entry(
        &self,
        doc: &mut VaultDocument,
        scope: String,
        description: String,
        secret: String,
        password: &str,
    ) -> Result<()> {
        // Validate scope
        if !utils::validate_scope_name(&scope) {
            return Err(VaultError::InvalidScope(scope));
        }

        // Parse scope path
        let scope_parts = utils::parse_scope_path(&scope);

        // Check if entry already exists
        if doc.find_entry(&scope_parts).is_some() {
            return Err(VaultError::EntryExists(scope));
        }

        // Encrypt the secret
        let (encrypted_content, salt) = self.crypto.encrypt(&secret, password)?;

        // Create new entry
        let entry = VaultEntry {
            scope_path: scope_parts.clone(),
            description,
            encrypted_content,
            salt: Some(salt),
            custom_fields: HashMap::new(),
        };

        // Add to document
        doc.add_entry(entry)
            .map_err(|e| VaultError::Other(e.to_string()))?;

        Ok(())
    }

    /// Update an existing entry.
    pub fn update_entry(
        &self,
        doc: &mut VaultDocument,
        scope: &[String],
        new_secret: Option<String>,
        new_description: Option<String>,
        password: &str,
    ) -> Result<()> {
        // Find entry
        let entry_idx = doc
            .entries
            .iter()
            .position(|e| e.scope_path == scope)
            .ok_or_else(|| VaultError::EntryNotFound(utils::format_scope_path(scope)))?;

        let entry = &mut doc.entries[entry_idx];

        // Update description if provided
        if let Some(desc) = new_description {
            entry.description = desc;
        }

        // Update secret if provided
        if let Some(secret) = new_secret {
            let (encrypted_content, salt) = self.crypto.encrypt(&secret, password)?;
            entry.encrypted_content = encrypted_content;
            entry.salt = Some(salt);
        }

        Ok(())
    }

    /// Delete an entry from the vault.
    pub fn delete_entry(&self, doc: &mut VaultDocument, scope: &[String]) -> Result<()> {
        // Find entry
        let entry_idx = doc
            .entries
            .iter()
            .position(|e| e.scope_path == scope)
            .ok_or_else(|| VaultError::EntryNotFound(utils::format_scope_path(scope)))?;

        // Remove entry
        doc.entries.remove(entry_idx);

        Ok(())
    }

    /// Decrypt an entry.
    pub fn decrypt_entry(&self, entry: &VaultEntry, password: &str) -> Result<String> {
        // Check if entry has encrypted content
        if entry.encrypted_content.is_empty() {
            return Err(VaultError::NoEncryptedContent(entry.scope_string()));
        }

        // Check if entry has salt
        let salt = entry
            .salt
            .as_ref()
            .ok_or_else(|| VaultError::NoSalt(entry.scope_string()))?;

        // Decrypt
        self.crypto
            .decrypt(&entry.encrypted_content, password, salt)
            .map_err(|_| VaultError::DecryptionFailed)
    }

    /// Rename an entry (change its scope).
    pub fn rename_entry(
        &self,
        doc: &mut VaultDocument,
        old_scope: &[String],
        new_scope: String,
    ) -> Result<()> {
        // Validate new scope
        if !utils::validate_scope_name(&new_scope) {
            return Err(VaultError::InvalidScope(new_scope));
        }

        let new_scope_parts = utils::parse_scope_path(&new_scope);

        // Check if new scope already exists
        if doc.find_entry(&new_scope_parts).is_some() {
            return Err(VaultError::EntryExists(new_scope));
        }

        // Find entry
        let entry = doc
            .entries
            .iter_mut()
            .find(|e| e.scope_path == old_scope)
            .ok_or_else(|| VaultError::EntryNotFound(utils::format_scope_path(old_scope)))?;

        // Update scope
        entry.scope_path = new_scope_parts.clone();

        Ok(())
    }

    /// Search entries by query.
    pub fn search_entries<'a>(
        &self,
        doc: &'a VaultDocument,
        query: &str,
        in_description: bool,
        case_sensitive: bool,
    ) -> Vec<&'a VaultEntry> {
        let query_lower = if case_sensitive {
            query.to_string()
        } else {
            query.to_lowercase()
        };

        doc.entries
            .iter()
            .filter(|entry| {
                let scope = entry.scope_string();
                let scope_check = if case_sensitive {
                    scope
                } else {
                    scope.to_lowercase()
                };

                let description_check = if case_sensitive {
                    entry.description.clone()
                } else {
                    entry.description.to_lowercase()
                };

                if in_description {
                    description_check.contains(&query_lower)
                } else {
                    scope_check.contains(&query_lower)
                }
            })
            .collect()
    }

    /// List all unique scopes in the vault.
    pub fn list_scopes(&self, doc: &VaultDocument) -> Vec<String> {
        // Preserve the order from the vault file
        let mut seen = std::collections::HashSet::new();
        let mut scopes = Vec::new();

        for entry in &doc.entries {
            let scope = entry.scope_string();
            if seen.insert(scope.clone()) {
                scopes.push(scope);
            }
        }

        scopes
    }

    /// Get entries filtered by scope prefix.
    pub fn get_entries_by_prefix<'a>(
        &self,
        doc: &'a VaultDocument,
        prefix: &[String],
    ) -> Vec<&'a VaultEntry> {
        doc.entries
            .iter()
            .filter(|entry| {
                entry.scope_path.len() >= prefix.len()
                    && entry.scope_path[..prefix.len()] == *prefix
            })
            .collect()
    }

    /// Export entries to JSON format (without secrets).
    pub fn export_metadata(&self, doc: &VaultDocument) -> serde_json::Value {
        let entries: Vec<_> = doc
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "scope": e.scope_string(),
                    "description": e.description,
                    "has_content": !e.encrypted_content.is_empty(),
                })
            })
            .collect();

        serde_json::json!({
            "version": "v1",
            "entry_count": entries.len(),
            "entries": entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_decrypt_entry() {
        let service = VaultService::new();
        let mut doc = VaultDocument::new();
        let password = "test_password";
        let secret = "my_secret_value";

        // Add entry
        service
            .add_entry(
                &mut doc,
                "test.entry".to_string(),
                "Test entry".to_string(),
                secret.to_string(),
                password,
            )
            .unwrap();

        // Find and decrypt
        let entry = doc
            .find_entry(&["test".to_string(), "entry".to_string()])
            .unwrap();
        let decrypted = service.decrypt_entry(entry, password).unwrap();

        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_search_entries() {
        let service = VaultService::new();
        let mut doc = VaultDocument::new();
        let password = "test_password";

        // Add some entries
        service
            .add_entry(
                &mut doc,
                "personal.email".to_string(),
                "Personal email account".to_string(),
                "secret1".to_string(),
                password,
            )
            .unwrap();

        service
            .add_entry(
                &mut doc,
                "work.email".to_string(),
                "Work email account".to_string(),
                "secret2".to_string(),
                password,
            )
            .unwrap();

        service
            .add_entry(
                &mut doc,
                "personal.banking".to_string(),
                "Banking credentials".to_string(),
                "secret3".to_string(),
                password,
            )
            .unwrap();

        // Search in scope
        let results = service.search_entries(&doc, "email", false, false);
        assert_eq!(results.len(), 2);

        // Search in description
        let results = service.search_entries(&doc, "account", true, false);
        assert_eq!(results.len(), 2);

        // Case sensitive search
        let results = service.search_entries(&doc, "EMAIL", false, true);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_rename_entry() {
        let service = VaultService::new();
        let mut doc = VaultDocument::new();
        let password = "test_password";

        // Add entry
        service
            .add_entry(
                &mut doc,
                "old.path".to_string(),
                "Test entry".to_string(),
                "secret".to_string(),
                password,
            )
            .unwrap();

        // Rename
        service
            .rename_entry(
                &mut doc,
                &["old".to_string(), "path".to_string()],
                "new.path".to_string(),
            )
            .unwrap();

        // Verify old path doesn't exist
        assert!(doc
            .find_entry(&["old".to_string(), "path".to_string()])
            .is_none());

        // Verify new path exists
        assert!(doc
            .find_entry(&["new".to_string(), "path".to_string()])
            .is_some());
    }
}
