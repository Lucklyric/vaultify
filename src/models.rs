//! Data models for the credential vault.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Represents a single entry in the vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultEntry {
    /// Scope path, e.g., ("personal", "banking", "chase")
    pub scope_path: Vec<String>,
    /// Markdown heading depth (1-6)
    pub heading_level: u8,
    /// Plain text description
    pub description: String,
    /// Base64 encrypted secret
    pub encrypted_content: String,
    /// Starting line in file (0-based)
    pub start_line: usize,
    /// Ending line in file (0-based)
    pub end_line: usize,
    /// Per-item salt for key derivation
    pub salt: Option<Vec<u8>>,
}

impl VaultEntry {
    /// Get scope as slash-separated string.
    pub fn scope_string(&self) -> String {
        self.scope_path.join("/")
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
    /// Original file lines with newlines
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
        use crate::parser::VaultParser;

        // Create parser for formatting
        let parser = VaultParser::new();

        // Format the new entry
        let entry_lines = parser.format_entry(&entry);

        // Find insertion point
        let parent_path = if entry.scope_path.len() > 1 {
            &entry.scope_path[..entry.scope_path.len() - 1]
        } else {
            &[]
        };

        let insert_point = VaultParser::find_insertion_point(self, parent_path);

        // Create any missing ancestors
        let ancestors = VaultParser::create_missing_ancestors(self, &entry.scope_path);

        // Insert ancestors first
        let mut current_insert = insert_point;
        for ancestor in ancestors {
            let ancestor_lines = parser.format_entry(&ancestor);
            for (i, line) in ancestor_lines.iter().enumerate() {
                self.raw_lines.insert(current_insert + i, line.clone());
            }
            current_insert += ancestor_lines.len();
            self.entries.push(ancestor);
        }

        // Insert the new entry
        for (i, line) in entry_lines.iter().enumerate() {
            self.raw_lines.insert(current_insert + i, line.clone());
        }

        // No need to add blank lines here since they're included in format_entry

        self.entries.push(entry);

        // Re-parse to update line numbers
        let content = self.raw_lines.join("");
        let new_doc = parser.parse(&content)?;
        self.entries = new_doc.entries;

        Ok(())
    }

    /// Save the document to a file.
    pub fn save(&self, path: &std::path::Path) -> Result<(), std::io::Error> {
        use std::fs;
        let content = self.raw_lines.join("");
        fs::write(path, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_entry_scope_string() {
        let entry = VaultEntry {
            scope_path: vec!["personal".to_string(), "banking".to_string()],
            heading_level: 2,
            description: "Banking info".to_string(),
            encrypted_content: "".to_string(),
            start_line: 0,
            end_line: 5,
            salt: None,
        };
        assert_eq!(entry.scope_string(), "personal/banking");
    }

    #[test]
    fn test_vault_entry_relationships() {
        let parent = VaultEntry {
            scope_path: vec!["personal".to_string()],
            heading_level: 1,
            description: "Personal".to_string(),
            encrypted_content: "".to_string(),
            start_line: 0,
            end_line: 5,
            salt: None,
        };

        let child = VaultEntry {
            scope_path: vec!["personal".to_string(), "banking".to_string()],
            heading_level: 2,
            description: "Banking".to_string(),
            encrypted_content: "".to_string(),
            start_line: 6,
            end_line: 10,
            salt: None,
        };

        assert!(parent.is_parent_of(&child));
        assert!(child.is_child_of(&parent));
        assert!(!child.is_parent_of(&parent));
        assert!(!parent.is_child_of(&child));
    }
}
