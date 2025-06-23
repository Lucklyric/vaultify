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
            version_pattern: Regex::new(r"<!--\s*vault-cli\s+(v\d+)\s*-->").unwrap(),
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
        "# root <!-- vault-cli v1 -->\n".to_string()
    }

    /// Parse vault content into a VaultDocument.
    pub fn parse(&self, content: &str) -> Result<VaultDocument, ParseError> {
        let lines: Vec<String> = content.lines().map(|s| format!("{}\n", s)).collect();
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
        let mut lines = Vec::new();

        // Add blank line before heading (except for root)
        if entry.heading_level > 1 {
            lines.push("\n".to_string());
        }

        // Heading
        let heading_prefix = "#".repeat(entry.heading_level as usize);
        let scope_string = entry.scope_string();
        lines.push(format!("{} {}\n", heading_prefix, scope_string));

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
            lines.push(format!("<encrypted salt=\"{}\">\n", salt_b64));
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
                    heading_level: ancestor_path.len() as u8,
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

    const SAMPLE_VAULT: &str = r#"# root <!-- vault-cli v1 -->

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
        let valid_vault = r#"# root <!-- vault-cli v1 -->
## test
<description/>
Test
</description>
<encrypted></encrypted>
"#;
        assert!(parser.parse(valid_vault).is_ok());

        // Invalid version
        let invalid_vault = r#"# root <!-- vault-cli v99 -->
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
            heading_level: 2,
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
}
