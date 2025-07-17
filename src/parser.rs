//! Order-preserving parser for vault markdown files.

use crate::crypto::VaultCrypto;
use crate::models::{VaultDocument, VaultEntry};
use regex::Regex;
use std::path::Path;
use thiserror::Error;

/// Errors that can occur during parsing.
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Unsupported vault version: {0}")]
    UnsupportedVersion(String),
    #[error("Invalid vault format")]
    InvalidFormat,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Parse and manipulate vault markdown files while preserving order.
pub struct VaultParser {
    // Supported versions
    supported_versions: Vec<&'static str>,
    #[allow(dead_code)]
    current_version: &'static str,
    // Regex patterns
    heading_pattern: Regex,
    version_pattern: Regex,
    description_start: Regex,
    description_end: Regex,
    encrypted_start: Regex,
    encrypted_end: Regex,
}

impl Default for VaultParser {
    fn default() -> Self {
        Self {
            supported_versions: vec!["v1"],
            current_version: "v1",
            heading_pattern: Regex::new(
                r"^(#{1,6})\s+(.+?)(?:\s*<!--\s*scope key:\s*(\S+)\s*-->)?$",
            )
            .unwrap(),
            version_pattern: Regex::new(r"<!--\s*vaultify\s+(v\d+)\s*-->").unwrap(),
            description_start: Regex::new(r"^<description/?>$").unwrap(),
            description_end: Regex::new(r"^</description>$").unwrap(),
            encrypted_start: Regex::new(r#"^<encrypted(?:\s+salt="([^"]+)")?>$"#).unwrap(),
            encrypted_end: Regex::new(r"^</encrypted>$").unwrap(),
        }
    }
}

impl VaultParser {
    /// Create a new parser instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new root document with version.
    pub fn create_root_document() -> String {
        "# root <!-- vaultify v1 -->\n".to_string()
    }

    /// Parse vault content into a VaultDocument.
    pub fn parse(&self, content: &str) -> Result<VaultDocument, ParseError> {
        let lines: Vec<String> = content.lines().map(|s| format!("{s}\n")).collect();
        let mut entries = Vec::new();

        // Extract and validate version
        if let Some(version) = self.extract_version(&lines) {
            if !self.supported_versions.contains(&version.as_str()) {
                return Err(ParseError::UnsupportedVersion(version));
            }
        }

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim_end();

            // Check if this is a heading
            if let Some(heading_match) = self.heading_pattern.captures(line) {
                let heading_text = heading_match.get(2).unwrap().as_str().trim();
                let heading_level = heading_match.get(1).unwrap().as_str().len();

                // Skip the root header (# root)
                if heading_level == 1 && heading_text.to_lowercase().starts_with("root") {
                    i += 1;
                    continue;
                }

                if let Some((entry, next_i)) = self.parse_entry(&lines, i, heading_match)? {
                    entries.push(entry);
                    i = next_i;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        Ok(VaultDocument {
            entries,
            raw_lines: lines,
            file_path: None,
        })
    }

    /// Parse a vault file.
    pub fn parse_file(&self, path: &Path) -> Result<VaultDocument, ParseError> {
        let content = std::fs::read_to_string(path)?;
        let mut doc = self.parse(&content)?;
        doc.file_path = Some(path.to_path_buf());
        Ok(doc)
    }

    /// Extract version from the first few lines.
    fn extract_version(&self, lines: &[String]) -> Option<String> {
        for line in lines.iter().take(5) {
            if let Some(version_match) = self.version_pattern.captures(line) {
                return Some(version_match.get(1).unwrap().as_str().to_string());
            }
        }
        None
    }

    /// Parse a single vault entry starting from a heading.
    fn parse_entry(
        &self,
        lines: &[String],
        start_idx: usize,
        heading_match: regex::Captures,
    ) -> Result<Option<(VaultEntry, usize)>, ParseError> {
        let heading_level = heading_match.get(1).unwrap().as_str().len() as u8;
        let heading_text = heading_match.get(2).unwrap().as_str().trim();

        // Remove the scope key comment from heading text if present
        let heading_text = if heading_text.contains("<!--") {
            heading_text.split("<!--").next().unwrap_or("").trim()
        } else {
            heading_text
        };

        // Parse scope path from heading text
        let scope_parts: Vec<String> = heading_text.split('/').map(|s| s.to_string()).collect();

        // Initialize entry data
        let mut description = String::new();
        let mut encrypted_content = String::new();
        let mut entry_salt = None;
        let mut current_idx = start_idx + 1;

        // State tracking
        let mut in_description = false;
        let mut in_encrypted = false;
        let mut description_lines = Vec::new();
        let mut encrypted_lines = Vec::new();

        // Find the end of this entry (next heading of same or higher level)
        while current_idx < lines.len() {
            let line = lines[current_idx].trim_end();

            // Check for next heading
            if self.heading_pattern.is_match(line) {
                break;
            }

            // Parse description block
            if self.description_start.is_match(line) {
                in_description = true;
                current_idx += 1;
                continue;
            } else if self.description_end.is_match(line) {
                in_description = false;
                description = description_lines.join("\n");
                current_idx += 1;
                continue;
            } else if in_description {
                description_lines.push(line.to_string());
                current_idx += 1;
                continue;
            }

            // Parse encrypted block
            if let Some(encrypted_match) = self.encrypted_start.captures(line) {
                in_encrypted = true;
                // Extract salt if present
                if let Some(salt_match) = encrypted_match.get(1) {
                    entry_salt =
                        Some(VaultCrypto::decode_salt(salt_match.as_str()).unwrap_or_default());
                }
                current_idx += 1;
                continue;
            } else if self.encrypted_end.is_match(line) {
                in_encrypted = false;
                encrypted_content = encrypted_lines.join("\n");
                current_idx += 1;
                continue;
            } else if in_encrypted {
                if !line.trim().is_empty() {
                    encrypted_lines.push(line.to_string());
                }
                current_idx += 1;
                continue;
            }

            current_idx += 1;
        }

        let entry = VaultEntry {
            scope_path: scope_parts,
            heading_level,
            description,
            encrypted_content,
            start_line: start_idx,
            end_line: current_idx.saturating_sub(1),
            salt: entry_salt,
        };

        Ok(Some((entry, current_idx)))
    }

    /// Format a vault entry as markdown lines.
    pub fn format_entry(&self, entry: &VaultEntry) -> Vec<String> {
        self.format_entry_with_context(entry, false)
    }

    /// Format a vault entry as markdown lines with context about position.
    pub fn format_entry_with_context(
        &self,
        entry: &VaultEntry,
        is_first_entry: bool,
    ) -> Vec<String> {
        let mut lines = Vec::new();

        // Add blank line before heading (except for the first entry after root)
        if entry.heading_level > 1 && !is_first_entry {
            lines.push("\n".to_string());
        }

        // Heading
        let heading_prefix = "#".repeat(entry.heading_level as usize);
        let scope_string = entry.scope_string();
        lines.push(format!("{heading_prefix} {scope_string}\n"));

        // Description block
        lines.push("<description/>\n".to_string());
        if !entry.description.is_empty() {
            lines.push(entry.description.clone());
            if !entry.description.ends_with('\n') {
                lines.push("\n".to_string());
            }
        }
        lines.push("</description>\n".to_string());

        // Encrypted block
        if let Some(salt) = &entry.salt {
            let salt_b64 = VaultCrypto::encode_salt(salt);
            lines.push(format!("<encrypted salt=\"{salt_b64}\">\n"));
        } else {
            lines.push("<encrypted>\n".to_string());
        }
        if !entry.encrypted_content.is_empty() {
            lines.push(entry.encrypted_content.clone());
            if !entry.encrypted_content.ends_with('\n') {
                lines.push("\n".to_string());
            }
        }
        lines.push("</encrypted>\n".to_string());

        lines
    }

    /// Find where to insert a new entry as the last child of parent.
    pub fn find_insertion_point(doc: &VaultDocument, parent_path: &[String]) -> usize {
        if parent_path.is_empty() {
            // Insert at end of file
            return doc.raw_lines.len();
        }

        // Find parent entry
        if let Some(parent_entry) = doc.find_entry(parent_path) {
            // Find the last child of parent
            let mut insert_after = parent_entry.end_line;
            let parent_level = parent_path.len();

            for entry in &doc.entries {
                // Check if this is a descendant of parent
                if entry.scope_path.len() > parent_level
                    && entry.scope_path[..parent_level] == *parent_path
                    && entry.start_line > parent_entry.start_line
                {
                    // Update insertion point to after this descendant
                    insert_after = insert_after.max(entry.end_line);
                }
            }

            // Insert after the last descendant
            if insert_after < doc.raw_lines.len() - 1 {
                insert_after + 1
            } else {
                doc.raw_lines.len()
            }
        } else {
            // Parent doesn't exist, insert at end
            doc.raw_lines.len()
        }
    }

    /// Create missing ancestor entries for a given scope path.
    pub fn create_missing_ancestors(doc: &VaultDocument, scope_path: &[String]) -> Vec<VaultEntry> {
        let mut ancestors_to_create = Vec::new();

        // Check each level of the path
        for i in 1..scope_path.len() {
            let ancestor_path = &scope_path[..i];
            if !doc.scope_exists(ancestor_path) {
                // Create ancestor entry
                let ancestor = VaultEntry {
                    scope_path: ancestor_path.to_vec(),
                    heading_level: (ancestor_path.len() + 1) as u8, // +1 because # root is level 1
                    description: format!("{} secrets", ancestor_path.join("/")),
                    encrypted_content: String::new(),
                    start_line: 0, // Will be set during insertion
                    end_line: 0,
                    salt: None,
                };
                ancestors_to_create.push(ancestor);
            }
        }

        ancestors_to_create
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_VAULT: &str = r#"# root <!-- vaultify v1 -->

## personal
<description/>
Personal accounts
</description>
<encrypted></encrypted>

### personal/email
<description/>
Email accounts
</description>
<encrypted salt="dGVzdHNhbHQ=">
gAAAAABk1234567890
</encrypted>

## work
<description/>
Work-related secrets
</description>
<encrypted></encrypted>
"#;

    #[test]
    fn test_parse_basic_vault() {
        let parser = VaultParser::new();
        let doc = parser.parse(SAMPLE_VAULT).unwrap();

        assert_eq!(doc.entries.len(), 3);

        let scopes: Vec<String> = doc.entries.iter().map(|e| e.scope_string()).collect();
        assert!(scopes.contains(&"personal".to_string()));
        assert!(scopes.contains(&"personal/email".to_string()));
        assert!(scopes.contains(&"work".to_string()));
    }

    #[test]
    fn test_parse_entry_with_salt() {
        let parser = VaultParser::new();
        let doc = parser.parse(SAMPLE_VAULT).unwrap();

        let email_entry = doc
            .find_entry(&["personal".to_string(), "email".to_string()])
            .unwrap();
        assert!(email_entry.salt.is_some());
        assert_eq!(email_entry.encrypted_content, "gAAAAABk1234567890");
    }

    #[test]
    fn test_version_validation() {
        let parser = VaultParser::new();

        // Valid version
        let valid_vault = r#"# root <!-- vaultify v1 -->
## test
<description/>
Test
</description>
<encrypted></encrypted>
"#;
        assert!(parser.parse(valid_vault).is_ok());

        // Invalid version
        let invalid_vault = r#"# root <!-- vaultify v99 -->
## test
<description/>
Test
</description>
<encrypted></encrypted>
"#;
        let result = parser.parse(invalid_vault);
        assert!(matches!(result, Err(ParseError::UnsupportedVersion(_))));
    }

    #[test]
    fn test_format_entry() {
        let entry = VaultEntry {
            scope_path: vec!["test".to_string(), "item".to_string()],
            heading_level: 3, // Should be 3 for nested entries (test/item)
            description: "Test entry".to_string(),
            encrypted_content: "encrypted_data".to_string(),
            salt: Some(b"test_salt_bytes".to_vec()),
            start_line: 0,
            end_line: 0,
        };

        let parser = VaultParser::new();
        let lines = parser.format_entry(&entry);
        let content = lines.join("");

        assert!(content.contains("## test/item"));
        assert!(content.contains("salt="));
        assert!(content.contains("encrypted_data"));
    }

    #[test]
    fn test_multiple_root_entries_save_reload() {
        use tempfile::TempDir;

        let parser = VaultParser::new();
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test_vault.md");

        // Create a vault with multiple root entries
        let mut doc = VaultDocument::new();

        // Add first root entry
        let entry1 = VaultEntry {
            scope_path: vec!["work".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "Work credentials".to_string(),
            encrypted_content: "encrypted_work_data".to_string(),
            salt: Some(b"work_salt".to_vec()),
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(entry1).unwrap();

        // Add second root entry
        let entry2 = VaultEntry {
            scope_path: vec!["personal".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "Personal accounts".to_string(),
            encrypted_content: "encrypted_personal_data".to_string(),
            salt: Some(b"personal_salt".to_vec()),
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(entry2).unwrap();

        // Add third root entry
        let entry3 = VaultEntry {
            scope_path: vec!["finance".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "Financial accounts".to_string(),
            encrypted_content: "encrypted_finance_data".to_string(),
            salt: Some(b"finance_salt".to_vec()),
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(entry3).unwrap();

        // Save the document
        doc.save(&vault_path).unwrap();

        // Print the saved content for debugging
        let saved_content = std::fs::read_to_string(&vault_path).unwrap();
        println!("Saved vault content:\n{}", saved_content);

        // Reload the document
        let reloaded_doc = parser.parse_file(&vault_path).unwrap();

        // Verify all entries were preserved
        assert_eq!(reloaded_doc.entries.len(), 3);

        // Verify each entry's data
        let work_entry = reloaded_doc.find_entry(&["work".to_string()]).unwrap();
        assert_eq!(work_entry.description, "Work credentials");
        assert_eq!(work_entry.encrypted_content, "encrypted_work_data");

        let personal_entry = reloaded_doc.find_entry(&["personal".to_string()]).unwrap();
        assert_eq!(personal_entry.description, "Personal accounts");
        assert_eq!(personal_entry.encrypted_content, "encrypted_personal_data");

        let finance_entry = reloaded_doc.find_entry(&["finance".to_string()]).unwrap();
        assert_eq!(finance_entry.description, "Financial accounts");
        assert_eq!(finance_entry.encrypted_content, "encrypted_finance_data");
    }

    #[test]
    fn test_multiple_root_entries_edge_cases() {
        use tempfile::TempDir;

        let parser = VaultParser::new();
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test_edge_cases.md");

        // Create vault content manually to test specific formatting issues
        let vault_content = r#"# root <!-- vaultify v1 -->

## work
<description/>
Work stuff
</description>
<encrypted salt="YmFzZTY0X3NhbHQ=">
YmFzZTY0X2VuY3J5cHRlZF9kYXRh
</encrypted>

## personal
<description/>
Personal items
</description>
<encrypted salt="YW5vdGhlcl9zYWx0">
YW5vdGhlcl9lbmNyeXB0ZWRfZGF0YQ==
</encrypted>

## finance
<description/>
Financial data
</description>
<encrypted salt="Zmlucy1YbHQ=">
ZmluYW5jZV9lbmNyeXB0ZWRfZGF0YQ==
</encrypted>
"#;

        // Write the vault content
        std::fs::write(&vault_path, vault_content).unwrap();

        // Parse it
        let doc = parser.parse_file(&vault_path).unwrap();
        assert_eq!(doc.entries.len(), 3);

        // Now save it again
        doc.save(&vault_path).unwrap();

        // Read the saved content
        let saved_content = std::fs::read_to_string(&vault_path).unwrap();
        println!("After re-save:\n{}", saved_content);

        // Try to parse again
        let reloaded_doc = parser.parse_file(&vault_path).unwrap();
        assert_eq!(reloaded_doc.entries.len(), 3);

        // Verify content integrity
        for (original, reloaded) in doc.entries.iter().zip(reloaded_doc.entries.iter()) {
            assert_eq!(original.scope_path, reloaded.scope_path);
            assert_eq!(original.description, reloaded.description);
            assert_eq!(original.encrypted_content, reloaded.encrypted_content);
        }
    }

    #[test]
    fn test_blank_line_formatting_bug() {
        use tempfile::TempDir;

        let parser = VaultParser::new();
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test_blank_lines.md");

        // Start with an empty vault
        let mut doc = VaultDocument::new();

        // Add first root entry - this should NOT have a blank line before it
        let entry1 = VaultEntry {
            scope_path: vec!["first".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "First entry".to_string(),
            encrypted_content: "data1".to_string(),
            salt: Some(b"salt1".to_vec()),
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(entry1).unwrap();

        // Check the formatting
        doc.save(&vault_path).unwrap();
        let content1 = std::fs::read_to_string(&vault_path).unwrap();
        println!("After first entry:\n{}", content1);

        // The first root entry should NOT have a blank line after the root header
        assert!(
            !content1.contains("# root <!-- vaultify v1 -->\n\n\n"),
            "First root entry should not have double blank line"
        );

        // Add second root entry
        let entry2 = VaultEntry {
            scope_path: vec!["second".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "Second entry".to_string(),
            encrypted_content: "data2".to_string(),
            salt: Some(b"salt2".to_vec()),
            start_line: 0,
            end_line: 0,
        };

        // Reload and add to ensure we test the full cycle
        let mut doc2 = parser.parse_file(&vault_path).unwrap();
        doc2.add_entry(entry2).unwrap();
        doc2.save(&vault_path).unwrap();

        let content2 = std::fs::read_to_string(&vault_path).unwrap();
        println!("After second entry:\n{}", content2);

        // Parse again to verify
        let final_doc = parser.parse_file(&vault_path).unwrap();
        assert_eq!(final_doc.entries.len(), 2);
    }

    #[test]
    fn test_empty_root_entries() {
        use tempfile::TempDir;

        let parser = VaultParser::new();
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test_empty_roots.md");

        let mut doc = VaultDocument::new();

        // Add empty root entries (no encrypted content)
        let entry1 = VaultEntry {
            scope_path: vec!["empty1".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "Empty container 1".to_string(),
            encrypted_content: String::new(),
            salt: None,
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(entry1).unwrap();

        let entry2 = VaultEntry {
            scope_path: vec!["empty2".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "Empty container 2".to_string(),
            encrypted_content: String::new(),
            salt: None,
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(entry2).unwrap();

        // Save and reload
        doc.save(&vault_path).unwrap();
        let reloaded = parser.parse_file(&vault_path).unwrap();

        assert_eq!(reloaded.entries.len(), 2);
        assert_eq!(reloaded.entries[0].encrypted_content, "");
        assert_eq!(reloaded.entries[1].encrypted_content, "");
    }

    #[test]
    fn test_special_characters_in_scope_names() {
        use tempfile::TempDir;

        let parser = VaultParser::new();
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test_special_chars.md");

        let mut doc = VaultDocument::new();

        // Add entries with special characters
        let entry1 = VaultEntry {
            scope_path: vec!["work-2024".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "Work with dash".to_string(),
            encrypted_content: "data1".to_string(),
            salt: Some(b"salt1".to_vec()),
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(entry1).unwrap();

        let entry2 = VaultEntry {
            scope_path: vec!["personal_backup".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "Personal with underscore".to_string(),
            encrypted_content: "data2".to_string(),
            salt: Some(b"salt2".to_vec()),
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(entry2).unwrap();

        let entry3 = VaultEntry {
            scope_path: vec!["email@domain".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "Email with at sign".to_string(),
            encrypted_content: "data3".to_string(),
            salt: Some(b"salt3".to_vec()),
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(entry3).unwrap();

        // Save and reload
        doc.save(&vault_path).unwrap();
        let reloaded = parser.parse_file(&vault_path).unwrap();

        assert_eq!(reloaded.entries.len(), 3);
        assert_eq!(reloaded.entries[0].scope_path[0], "work-2024");
        assert_eq!(reloaded.entries[1].scope_path[0], "personal_backup");
        assert_eq!(reloaded.entries[2].scope_path[0], "email@domain");
    }

    #[test]
    fn test_many_root_entries() {
        use tempfile::TempDir;

        let parser = VaultParser::new();
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test_many_roots.md");

        let mut doc = VaultDocument::new();

        // Add 10 root entries
        for i in 0..10 {
            let entry = VaultEntry {
                scope_path: vec![format!("root{}", i)],
                heading_level: 2, // Should be 2 for root-level entries
                description: format!("Root entry {}", i),
                encrypted_content: format!("data{}", i),
                salt: Some(format!("salt{}", i).as_bytes().to_vec()),
                start_line: 0,
                end_line: 0,
            };
            doc.add_entry(entry).unwrap();
        }

        // Save and reload multiple times to test stability
        for _ in 0..3 {
            doc.save(&vault_path).unwrap();
            doc = parser.parse_file(&vault_path).unwrap();
        }

        // Verify all entries preserved
        assert_eq!(doc.entries.len(), 10);
        for i in 0..10 {
            assert_eq!(doc.entries[i].scope_path[0], format!("root{}", i));
            assert_eq!(doc.entries[i].encrypted_content, format!("data{}", i));
        }
    }

    #[test]
    fn test_root_entries_with_children() {
        use tempfile::TempDir;

        let parser = VaultParser::new();
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test_vault_nested.md");

        // Create a vault with root entries that have children
        let mut doc = VaultDocument::new();

        // Add first root entry
        let work_root = VaultEntry {
            scope_path: vec!["work".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "Work credentials".to_string(),
            encrypted_content: String::new(),
            salt: None,
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(work_root).unwrap();

        // Add child of work
        let work_email = VaultEntry {
            scope_path: vec!["work".to_string(), "email".to_string()],
            heading_level: 3,
            description: "Work email".to_string(),
            encrypted_content: "encrypted_work_email".to_string(),
            salt: Some(b"work_email_salt".to_vec()),
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(work_email).unwrap();

        // Add second root entry
        let personal_root = VaultEntry {
            scope_path: vec!["personal".to_string()],
            heading_level: 2, // Should be 2 for root-level entries
            description: "Personal accounts".to_string(),
            encrypted_content: String::new(),
            salt: None,
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(personal_root).unwrap();

        // Add child of personal
        let personal_bank = VaultEntry {
            scope_path: vec!["personal".to_string(), "bank".to_string()],
            heading_level: 3,
            description: "Personal banking".to_string(),
            encrypted_content: "encrypted_bank_data".to_string(),
            salt: Some(b"bank_salt".to_vec()),
            start_line: 0,
            end_line: 0,
        };
        doc.add_entry(personal_bank).unwrap();

        // Save and reload
        doc.save(&vault_path).unwrap();
        let reloaded_doc = parser.parse_file(&vault_path).unwrap();

        // Verify structure
        assert_eq!(reloaded_doc.entries.len(), 4);

        // Verify root entries
        assert!(reloaded_doc.find_entry(&["work".to_string()]).is_some());
        assert!(reloaded_doc.find_entry(&["personal".to_string()]).is_some());

        // Verify children
        let work_email_entry = reloaded_doc
            .find_entry(&["work".to_string(), "email".to_string()])
            .unwrap();
        assert_eq!(work_email_entry.encrypted_content, "encrypted_work_email");

        let bank_entry = reloaded_doc
            .find_entry(&["personal".to_string(), "bank".to_string()])
            .unwrap();
        assert_eq!(bank_entry.encrypted_content, "encrypted_bank_data");
    }
}
