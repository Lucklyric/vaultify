//! TOML format parser for vault files with flexible parsing support.

use crate::crypto::VaultCrypto;
use crate::error::{Result, VaultError};
use crate::models::{VaultDocument, VaultEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use toml::value::Table;

/// TOML format metadata
#[derive(Debug, Serialize, Deserialize)]
struct VaultMetadata {
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified: Option<String>,
}

/// TOML entry structure
#[derive(Debug, Serialize, Deserialize)]
struct TomlEntry {
    description: String,
    #[serde(default)]
    encrypted: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
    #[serde(flatten)]
    custom_fields: HashMap<String, toml::Value>,
}

/// Parse and manipulate vault TOML files with flexible parsing.
pub struct TomlParser {
    supported_versions: Vec<&'static str>,
    current_version: &'static str,
}

impl Default for TomlParser {
    fn default() -> Self {
        Self {
            supported_versions: vec!["v0.3"],
            current_version: "v0.3",
        }
    }
}

impl TomlParser {
    /// Create a new parser instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse vault content into a VaultDocument.
    pub fn parse(&self, content: &str) -> Result<VaultDocument> {
        // Parse TOML with order preservation
        let table: Table = content
            .parse()
            .map_err(|e| VaultError::Other(format!("TOML parse error: {}", e)))?;

        // Check version
        if let Some(version) = table.get("version").and_then(|v| v.as_str()) {
            if !self.supported_versions.contains(&version) {
                return Err(VaultError::Other(format!(
                    "Unsupported TOML version: {}",
                    version
                )));
            }
        }

        let mut entries = Vec::new();
        let mut processed_keys = std::collections::HashSet::new();

        // Process all table entries recursively
        self.process_tables(&table, &[], &mut entries, &mut processed_keys)?;

        // Sort entries by scope path for consistent ordering
        entries.sort_by(|a, b| a.scope_path.cmp(&b.scope_path));

        Ok(VaultDocument {
            entries,
            raw_lines: vec![], // Not used in TOML mode
            file_path: None,
        })
    }

    /// Parse a vault file.
    pub fn parse_file(&self, path: &Path) -> Result<VaultDocument> {
        let content = std::fs::read_to_string(path).map_err(VaultError::Io)?;
        let mut doc = self.parse(&content)?;
        doc.file_path = Some(path.to_path_buf());
        Ok(doc)
    }

    /// Format a VaultDocument as TOML.
    pub fn format(&self, doc: &VaultDocument) -> String {
        let mut root = toml::Table::new();

        // Add metadata
        root.insert(
            "version".to_string(),
            toml::Value::String(self.current_version.to_string()),
        );

        // Get current timestamp
        let now = chrono::Utc::now().to_rfc3339();
        root.insert("modified".to_string(), toml::Value::String(now));

        // Add entries
        for entry in &doc.entries {
            let key = entry.scope_path.join(".");
            let mut entry_table = toml::Table::new();

            // Core fields
            entry_table.insert(
                "description".to_string(),
                toml::Value::String(entry.description.clone()),
            );
            entry_table.insert(
                "encrypted".to_string(),
                toml::Value::String(entry.encrypted_content.clone()),
            );

            if let Some(salt) = &entry.salt {
                entry_table.insert(
                    "salt".to_string(),
                    toml::Value::String(VaultCrypto::encode_salt(salt)),
                );
            }

            // Custom fields
            for (k, v) in &entry.custom_fields {
                entry_table.insert(k.clone(), v.clone());
            }

            root.insert(key, toml::Value::Table(entry_table));
        }

        toml::to_string_pretty(&root).unwrap_or_default()
    }

    /// Update an entry preserving custom fields.
    pub fn update_entry(
        doc: &mut VaultDocument,
        scope_path: &[String],
        updates: HashMap<String, toml::Value>,
    ) -> Result<()> {
        let entry = doc
            .find_entry_mut(scope_path)
            .ok_or_else(|| VaultError::EntryNotFound(scope_path.join("/")))?;

        // Update only specified fields
        for (key, value) in updates {
            match key.as_str() {
                "description" => {
                    if let Some(desc) = value.as_str() {
                        entry.description = desc.to_string();
                    }
                }
                "encrypted" => {
                    if let Some(enc) = value.as_str() {
                        entry.encrypted_content = enc.to_string();
                    }
                }
                "salt" => {
                    if let Some(salt_str) = value.as_str() {
                        entry.salt = VaultCrypto::decode_salt(salt_str).ok();
                    }
                }
                _ => {
                    // Store in custom fields
                    entry.custom_fields.insert(key, value);
                }
            }
        }

        Ok(())
    }

    /// Process tables recursively, handling both flat and nested structures.
    #[allow(clippy::only_used_in_recursion)]
    fn process_tables(
        &self,
        table: &Table,
        prefix: &[String],
        entries: &mut Vec<VaultEntry>,
        processed_keys: &mut std::collections::HashSet<String>,
    ) -> Result<()> {
        for (key, value) in table {
            // Skip metadata fields at root level
            if prefix.is_empty() && (key == "version" || key == "created" || key == "modified") {
                continue;
            }

            // Build full scope path
            let mut scope_parts = prefix.to_vec();
            let key_parts = parse_scope_key(key);
            scope_parts.extend(key_parts);

            let full_key = scope_parts.join(".");

            if let Some(nested_table) = value.as_table() {
                // Check if this is a vault entry (has description/encrypted/salt)
                let is_vault_entry = nested_table.contains_key("description")
                    || nested_table.contains_key("encrypted")
                    || nested_table.contains_key("salt");

                if is_vault_entry && !processed_keys.contains(&full_key) {
                    // Create implicit parent entries
                    for i in 1..scope_parts.len() {
                        let parent_path = scope_parts[..i].to_vec();
                        let parent_key = parent_path.join(".");

                        if !processed_keys.contains(&parent_key) {
                            let parent_entry = VaultEntry {
                                scope_path: parent_path.clone(),
                                heading_level: 0,
                                description: format!("{} secrets", parent_path.join("/")),
                                encrypted_content: String::new(),
                                salt: None,
                                start_line: 0,
                                end_line: 0,
                                custom_fields: HashMap::new(),
                            };
                            entries.push(parent_entry);
                            processed_keys.insert(parent_key);
                        }
                    }

                    // Process this entry
                    let toml_entry = extract_toml_entry(nested_table)?;
                    let entry = VaultEntry {
                        scope_path: scope_parts.clone(),
                        heading_level: 0,
                        description: toml_entry.description,
                        encrypted_content: toml_entry.encrypted,
                        salt: toml_entry
                            .salt
                            .and_then(|s| VaultCrypto::decode_salt(&s).ok()),
                        start_line: 0,
                        end_line: 0,
                        custom_fields: toml_entry.custom_fields,
                    };
                    entries.push(entry);
                    processed_keys.insert(full_key);
                }

                // Process nested tables (for structures like [work] with [work.email] inside)
                self.process_tables(nested_table, &scope_parts, entries, processed_keys)?;
            }
        }

        Ok(())
    }
}

/// Parse a scope key that may contain dots
fn parse_scope_key(key: &str) -> Vec<String> {
    // For now, simple split by dots
    // TODO: Handle quoted keys with dots inside
    key.split('.').map(|s| s.to_string()).collect()
}

/// Extract TomlEntry from a table
fn extract_toml_entry(table: &Table) -> Result<TomlEntry> {
    let description = table
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let encrypted = table
        .get("encrypted")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let salt = table
        .get("salt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Collect custom fields
    let mut custom_fields = HashMap::new();
    for (k, v) in table {
        if k != "description" && k != "encrypted" && k != "salt" {
            custom_fields.insert(k.clone(), v.clone());
        }
    }

    Ok(TomlEntry {
        description,
        encrypted,
        salt,
        custom_fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_toml() {
        let content = r#"
version = "v0.3"

[work]
description = "Work credentials"
encrypted = ""
salt = ""

[work.email]
description = "Work email"
encrypted = "YmFzZTY0X2VuY3J5cHRlZF9kYXRh"
salt = "YmFzZTY0X3NhbHQ="
"#;

        let parser = TomlParser::new();
        let doc = parser.parse(content).unwrap();

        assert_eq!(doc.entries.len(), 2);
        assert_eq!(doc.entries[0].scope_path, vec!["work"]);
        assert_eq!(doc.entries[1].scope_path, vec!["work", "email"]);
    }

    #[test]
    fn test_implicit_parent_creation() {
        let content = r#"
version = "v0.3"

[work.databases.production]
description = "Production DB"
encrypted = "encrypted_data"
salt = "salt_data"
"#;

        let parser = TomlParser::new();
        let doc = parser.parse(content).unwrap();

        // Should create implicit parents
        assert_eq!(doc.entries.len(), 3);
        assert_eq!(doc.entries[0].scope_path, vec!["work"]);
        assert_eq!(doc.entries[1].scope_path, vec!["work", "databases"]);
        assert_eq!(
            doc.entries[2].scope_path,
            vec!["work", "databases", "production"]
        );
    }

    #[test]
    fn test_custom_fields_preservation() {
        let content = r#"
version = "v0.3"

[personal.banking]
description = "Banking credentials"
encrypted = "encrypted_data"
salt = "salt_data"
expires = "2025-12-31"
priority = "high"
tags = ["finance", "important"]
"#;

        let parser = TomlParser::new();
        let doc = parser.parse(content).unwrap();

        let banking_entry = doc
            .find_entry(&["personal".to_string(), "banking".to_string()])
            .unwrap();
        assert_eq!(
            banking_entry.custom_fields.get("expires").unwrap().as_str(),
            Some("2025-12-31")
        );
        assert_eq!(
            banking_entry
                .custom_fields
                .get("priority")
                .unwrap()
                .as_str(),
            Some("high")
        );
        assert!(banking_entry.custom_fields.contains_key("tags"));
    }

    #[test]
    fn test_format_document() {
        let mut doc = VaultDocument::new();

        // Add entry with custom fields
        let mut custom_fields = HashMap::new();
        custom_fields.insert(
            "expires".to_string(),
            toml::Value::String("2025-12-31".to_string()),
        );

        let entry = VaultEntry {
            scope_path: vec!["work".to_string(), "email".to_string()],
            heading_level: 0,
            description: "Work email".to_string(),
            encrypted_content: "encrypted".to_string(),
            salt: Some(b"salt".to_vec()),
            start_line: 0,
            end_line: 0,
            custom_fields,
        };

        doc.entries.push(entry);

        let parser = TomlParser::new();
        let formatted = parser.format(&doc);

        assert!(formatted.contains("version = \"v0.3\""));
        assert!(formatted.contains("[\"work.email\"]")); // TOML quotes keys with dots
        assert!(formatted.contains("description = \"Work email\""));
        assert!(formatted.contains("expires = \"2025-12-31\""));
    }
}
