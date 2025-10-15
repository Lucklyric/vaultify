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
            supported_versions: vec!["v0.3", "v0.3.1", "v0.4.0"],
            current_version: "v0.4.0",
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
        let table: Table = content.parse().map_err(|e| {
            // T078-T079: Enhance error message with scope detection
            let error_msg = format!("{e}");
            let enhanced_msg = self.enhance_parse_error(&error_msg, content);
            VaultError::Other(enhanced_msg)
        })?;

        // Check version
        if let Some(version) = table.get("version").and_then(|v| v.as_str()) {
            if !self.supported_versions.contains(&version) {
                return Err(VaultError::Other(format!(
                    "Unsupported TOML version: {version}"
                )));
            }
        }

        let mut entries = Vec::new();
        let mut processed_keys = std::collections::HashSet::new();

        // Process all table entries recursively
        self.process_tables(&table, &[], &mut entries, &mut processed_keys)?;

        // Preserve original insertion order - no sorting

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
        // Build hierarchical structure for proper TOML dotted keys
        let mut lines = Vec::new();

        // Add metadata at the top
        lines.push(format!("version = \"{}\"", self.current_version));
        let now = chrono::Utc::now().to_rfc3339();
        lines.push(format!("modified = \"{now}\""));
        lines.push(String::new()); // blank line

        // Preserve exact file order - no sorting at all
        // New entries are added to the end of their group naturally during parsing
        let sorted_entries = &doc.entries;

        // Format each entry with proper TOML dotted key notation
        for entry in sorted_entries {
            // Skip empty parent entries that only exist for hierarchy
            if entry.encrypted_content.is_empty() && entry.description.ends_with(" secrets") {
                continue;
            }

            // Create the dotted key section header
            let section_key = entry.scope_path.join(".");
            lines.push(format!("[{section_key}]"));

            // Add fields
            // Use multiline string format for descriptions with newlines
            if entry.description.contains('\n') {
                // Use TOML multi-line literal string (triple quotes)
                lines.push(format!("description = '''\n{}'''", entry.description));
            } else {
                lines.push(format!(
                    "description = \"{}\"",
                    escape_toml_string(&entry.description)
                ));
            }

            // Always include encrypted field
            if !entry.encrypted_content.is_empty() {
                lines.push(format!("encrypted = \"{}\"", entry.encrypted_content));
            } else {
                lines.push("encrypted = \"\"".to_string());
            }

            // Always include salt field for consistency
            if let Some(salt) = &entry.salt {
                lines.push(format!("salt = \"{}\"", VaultCrypto::encode_salt(salt)));
            } else {
                lines.push("salt = \"\"".to_string());
            }

            // Add custom fields
            for (k, v) in &entry.custom_fields {
                lines.push(format!("{k} = {}", format_toml_value(v)));
            }

            lines.push(String::new()); // blank line between entries
        }

        lines.join("\n")
    }

    /// Update an entry preserving custom fields.
    pub fn update_entry(
        doc: &mut VaultDocument,
        scope_path: &[String],
        updates: HashMap<String, toml::Value>,
    ) -> Result<()> {
        let entry = doc
            .find_entry_mut(scope_path)
            .ok_or_else(|| VaultError::EntryNotFound(scope_path.join(".")))?;

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
                                description: format!("{} secrets", parent_path.join(".")),
                                encrypted_content: String::new(),
                                salt: None,
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
                        description: toml_entry.description,
                        encrypted_content: toml_entry.encrypted,
                        salt: toml_entry
                            .salt
                            .and_then(|s| VaultCrypto::decode_salt(&s).ok()),
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

    /// Enhance TOML parse error messages with scope detection (T078-T079)
    fn enhance_parse_error(&self, original_error: &str, content: &str) -> String {
        use regex::Regex;

        let mut enhanced = format!("Failed to parse vault file: {original_error}");

        // Try to detect invalid scope names using regex
        let section_regex = Regex::new(r"\[([^\]]+)\]").unwrap();

        for line in content.lines() {
            if let Some(captures) = section_regex.captures(line) {
                let scope = captures.get(1).unwrap().as_str();

                // Check if scope contains invalid characters
                if scope.contains(' ') {
                    enhanced.push_str(&format!("\n\nSuspected invalid scope: '{scope}'"));
                    enhanced.push_str("\nIssue: Spaces are not supported in scope names");
                    enhanced.push_str(&format!(
                        "\nSuggestion: Use '{}' instead of '{}'",
                        scope.replace(' ', "."),
                        scope
                    ));
                    enhanced.push_str(
                        "\n\nTo check all invalid scopes before fixing, run: vaultify validate",
                    );
                    break;
                }
            }
        }

        enhanced
    }
}

/// Parse a scope key that may contain dots
fn parse_scope_key(key: &str) -> Vec<String> {
    // For now, simple split by dots
    // TODO: Handle quoted keys with dots inside
    key.split('.').map(|s| s.to_string()).collect()
}

/// Escape a string for TOML format
fn escape_toml_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Format a TOML value for output
fn format_toml_value(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => {
            if s.contains('\n') {
                // Use TOML multi-line literal string
                format!("'''\n{s}'''")
            } else {
                format!("\"{}\"", escape_toml_string(s))
            }
        }
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_toml_value).collect();
            format!("[{}]", items.join(", "))
        }
        toml::Value::Datetime(dt) => format!("\"{dt}\""),
        toml::Value::Table(_) => "{ ... }".to_string(), // Shouldn't happen for custom fields
    }
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

    // Collect custom fields (excluding nested tables)
    let mut custom_fields = HashMap::new();
    for (k, v) in table {
        if k != "description" && k != "encrypted" && k != "salt" {
            // Skip nested tables - they are separate vault entries
            if !v.is_table() {
                custom_fields.insert(k.clone(), v.clone());
            }
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
    fn test_insertion_order_preservation() {
        let parser = TomlParser::new();

        // Create entries in a specific order
        let doc = VaultDocument {
            entries: vec![
                VaultEntry {
                    scope_path: vec!["a".to_string()],
                    description: "Root A".to_string(),
                    encrypted_content: String::new(),
                    salt: None,
                    custom_fields: HashMap::new(),
                },
                VaultEntry {
                    scope_path: vec!["a".to_string(), "a3".to_string()],
                    description: "Third child".to_string(),
                    encrypted_content: "encrypted3".to_string(),
                    salt: Some(vec![3, 3, 3]),
                    custom_fields: HashMap::new(),
                },
                VaultEntry {
                    scope_path: vec!["a".to_string(), "a1".to_string()],
                    description: "First child".to_string(),
                    encrypted_content: "encrypted1".to_string(),
                    salt: Some(vec![1, 1, 1]),
                    custom_fields: HashMap::new(),
                },
                VaultEntry {
                    scope_path: vec!["a".to_string(), "a2".to_string()],
                    description: "Second child".to_string(),
                    encrypted_content: "encrypted2".to_string(),
                    salt: Some(vec![2, 2, 2]),
                    custom_fields: HashMap::new(),
                },
            ],
            raw_lines: vec![],
            file_path: None,
        };

        let formatted = parser.format(&doc);

        // Find the positions of each entry in the output
        let a_pos = formatted.find("[a]").expect("Should find [a]");
        let a1_pos = formatted.find("[a.a1]").expect("Should find [a.a1]");
        let a2_pos = formatted.find("[a.a2]").expect("Should find [a.a2]");
        let a3_pos = formatted.find("[a.a3]").expect("Should find [a.a3]");

        // Verify parent comes first
        assert!(a_pos < a1_pos);
        assert!(a_pos < a2_pos);
        assert!(a_pos < a3_pos);

        // Verify children maintain exact insertion order (a3, a1, a2)
        assert!(
            a3_pos < a1_pos,
            "a3 should come before a1 (insertion order)"
        );
        assert!(
            a1_pos < a2_pos,
            "a1 should come before a2 (insertion order)"
        );
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
            description: "Work email".to_string(),
            encrypted_content: "encrypted".to_string(),
            salt: Some(b"salt".to_vec()),
            custom_fields,
        };

        doc.entries.push(entry);

        let parser = TomlParser::new();
        let formatted = parser.format(&doc);

        assert!(formatted.contains("version = \"v0.4.0\""));
        assert!(formatted.contains("[work.email]")); // Now using native TOML dotted notation
        assert!(formatted.contains("description = \"Work email\""));
        assert!(formatted.contains("expires = \"2025-12-31\""));
    }
}
