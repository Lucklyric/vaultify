//! Data models for the credential vault.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Represents a single entry in the vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultEntry {
    /// Scope path, e.g., ("personal", "banking", "chase")
    pub scope_path: Vec<String>,
    /// Plain text description
    pub description: String,
    /// Base64 encrypted secret
    pub encrypted_content: String,
    /// Per-item salt for key derivation
    pub salt: Option<Vec<u8>>,
    /// Custom fields for extensibility (TOML format)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub custom_fields: HashMap<String, toml::Value>,
}

impl VaultEntry {
    /// Get scope as dot-separated string.
    pub fn scope_string(&self) -> String {
        self.scope_path.join(".")
    }

    /// Check if this entry has encrypted content.
    pub fn is_leaf(&self) -> bool {
        !self.encrypted_content.trim().is_empty()
    }

    /// Check if this entry is a parent of another.
    pub fn is_parent_of(&self, other: &VaultEntry) -> bool {
        if self.scope_path.len() >= other.scope_path.len() {
            return false;
        }
        other.scope_path[..self.scope_path.len()] == self.scope_path
    }

    /// Check if this entry is a child of another.
    pub fn is_child_of(&self, other: &VaultEntry) -> bool {
        other.is_parent_of(self)
    }
}

/// Represents the entire vault document.
#[derive(Debug, Clone)]
pub struct VaultDocument {
    /// All vault entries in order
    pub entries: Vec<VaultEntry>,
    /// Raw lines (not used in TOML format, kept for compatibility)
    pub raw_lines: Vec<String>,
    /// Path to the vault file
    pub file_path: Option<PathBuf>,
}

impl Default for VaultDocument {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            raw_lines: vec!["# root <!-- vaultify v1 -->\n".to_string()],
            file_path: None,
        }
    }
}

impl VaultDocument {
    /// Create a new empty vault document.
    pub fn new() -> Self {
        Self::default()
    }

    /// Find entry by scope path.
    pub fn find_entry(&self, scope_path: &[String]) -> Option<&VaultEntry> {
        self.entries
            .iter()
            .find(|entry| entry.scope_path == scope_path)
    }

    /// Find entry by scope path (mutable).
    pub fn find_entry_mut(&mut self, scope_path: &[String]) -> Option<&mut VaultEntry> {
        self.entries
            .iter_mut()
            .find(|entry| entry.scope_path == scope_path)
    }

    /// Find all direct children of a parent scope.
    pub fn find_children(&self, parent_path: &[String]) -> Vec<&VaultEntry> {
        let parent_level = parent_path.len();
        self.entries
            .iter()
            .filter(|entry| {
                entry.scope_path.len() == parent_level + 1
                    && entry.scope_path[..parent_level] == *parent_path
            })
            .collect()
    }

    /// Get all scope paths as strings.
    pub fn get_all_scopes(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.scope_string()).collect()
    }

    /// Check if a scope already exists.
    pub fn scope_exists(&self, scope_path: &[String]) -> bool {
        self.find_entry(scope_path).is_some()
    }

    /// Add a new entry to the document.
    pub fn add_entry(&mut self, entry: VaultEntry) -> Result<(), Box<dyn std::error::Error>> {
        // Find the correct position to insert within the group
        // We want to maintain group cohesion - all entries with the same top-level
        // prefix should be together, with new entries added at the end of their group

        if self.entries.is_empty() {
            self.entries.push(entry);
            return Ok(());
        }

        // Get the top-level prefix of the new entry
        let new_prefix = &entry.scope_path[0];

        // Find the last index of entries with the same top-level prefix
        let mut insert_position = None;
        for (i, existing) in self.entries.iter().enumerate() {
            if !existing.scope_path.is_empty() && &existing.scope_path[0] == new_prefix {
                // Found an entry with the same prefix, update insert position
                insert_position = Some(i + 1);
            }
        }

        // If we found entries with the same prefix, insert after the last one
        // Otherwise, append to the end
        match insert_position {
            Some(pos) => self.entries.insert(pos, entry),
            None => self.entries.push(entry),
        }

        Ok(())
    }

    /// Save the document to a file.
    pub fn save(&self, _path: &std::path::Path) -> Result<(), std::io::Error> {
        // This method is no longer used - saving is handled by VaultService
        // which uses TomlParser::format() to generate the content
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_entry_scope_string() {
        let entry = VaultEntry {
            scope_path: vec!["personal".to_string(), "banking".to_string()],
            description: "Banking info".to_string(),
            encrypted_content: "".to_string(),
            salt: None,
            custom_fields: HashMap::new(),
        };
        assert_eq!(entry.scope_string(), "personal.banking");
    }

    #[test]
    fn test_vault_entry_relationships() {
        let parent = VaultEntry {
            scope_path: vec!["personal".to_string()],
            description: "Personal".to_string(),
            encrypted_content: "".to_string(),
            salt: None,
            custom_fields: HashMap::new(),
        };

        let child = VaultEntry {
            scope_path: vec!["personal".to_string(), "banking".to_string()],
            description: "Banking".to_string(),
            encrypted_content: "".to_string(),
            salt: None,
            custom_fields: HashMap::new(),
        };

        assert!(parent.is_parent_of(&child));
        assert!(child.is_child_of(&parent));
        assert!(!child.is_parent_of(&parent));
        assert!(!parent.is_child_of(&child));
    }
}

// ============================================================================
// User Story 3: Validation Models (T085-T089)
// ============================================================================

use crate::error::ScopeValidationError;
use std::fmt;

/// Represents a single validation issue in a vault file
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    /// Line number in the vault file where the issue was found
    pub line_number: usize,
    /// The invalid scope name
    pub scope: String,
    /// The validation error details
    pub error: ScopeValidationError,
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Line {}: [{}]", self.line_number, self.scope)?;
        write!(f, "  {}", self.error)
    }
}

/// Report of vault file validation results
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// Path to the validated vault file
    pub file_path: PathBuf,
    /// List of validation issues found
    pub issues: Vec<ValidationIssue>,
    /// Optional TOML parse error if file couldn't be parsed
    pub parse_error: Option<String>,
    /// Vault version if parseable
    pub vault_version: Option<String>,
}

impl ValidationReport {
    /// Check if the vault is valid (no issues)
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty() && self.parse_error.is_none()
    }

    /// Get appropriate exit code (0 for valid, 1 for invalid)
    pub fn exit_code(&self) -> i32 {
        if self.is_valid() {
            0
        } else {
            1
        }
    }
}
