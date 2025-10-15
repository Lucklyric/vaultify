//! Shared operations between CLI and interactive modes.

use crate::error::{Result, VaultError};
use crate::models::VaultDocument;
use crate::security::ClipboardManager;
use crate::service::VaultService;
use crate::utils::{self, success};
use colored::*;
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroize;

/// Result of a list operation.
pub struct ListResult {
    pub entries: Vec<EntryInfo>,
}

/// Information about a vault entry.
pub struct EntryInfo {
    pub scope: String,
    pub description: String,
    pub has_content: bool,
}

/// Result of a decrypt operation.
pub struct DecryptResult {
    pub scope: String,
    pub description: String,
    pub plaintext: String,
}

/// Shared operations for vault management.
pub struct VaultOperations {
    service: VaultService,
}

impl Default for VaultOperations {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultOperations {
    /// Create a new operations instance.
    pub fn new() -> Self {
        Self {
            service: VaultService::new(),
        }
    }

    /// Load vault to verify structure.
    pub fn load_vault(&self, vault_path: &Path) -> Result<VaultDocument> {
        self.service.load_vault(vault_path)
    }

    /// List vault entries with optional filter.
    pub fn list_entries(&self, vault_path: &Path, filter: Option<&str>) -> Result<ListResult> {
        let doc = self.service.load_vault(vault_path)?;

        // Get all entries with their status
        let mut entries: Vec<EntryInfo> = doc
            .entries
            .iter()
            .map(|e| EntryInfo {
                scope: e.scope_string(),
                description: e.description.clone(),
                has_content: !e.encrypted_content.trim().is_empty(),
            })
            .collect();

        // Apply filter if provided - search in both scope and description
        if let Some(query) = filter {
            let query_lower = query.to_lowercase();
            entries.retain(|entry| {
                let scope_match = entry.scope.to_lowercase().contains(&query_lower);
                let desc_match = entry.description.to_lowercase().contains(&query_lower);
                scope_match || desc_match
            });
        }

        // Preserve the order from the vault file - no sorting

        Ok(ListResult { entries })
    }

    /// Add a new entry to the vault.
    pub fn add_entry(
        &self,
        vault_path: &Path,
        scope: &str,
        description: &str,
        secret: &str,
        password: &str,
    ) -> Result<()> {
        let mut doc = self.service.load_vault(vault_path)?;

        self.service.add_entry(
            &mut doc,
            scope.to_string(),
            description.to_string(),
            secret.to_string(),
            password,
        )?;

        self.service.save_vault(&doc, vault_path)?;
        Ok(())
    }

    /// Decrypt an entry.
    pub fn decrypt_entry(
        &self,
        vault_path: &Path,
        scope: &str,
        password: &str,
    ) -> Result<DecryptResult> {
        let doc = self.service.load_vault(vault_path)?;
        let scope_parts = utils::parse_scope_path(scope);

        let entry = doc
            .find_entry(&scope_parts)
            .ok_or_else(|| VaultError::EntryNotFound(scope.to_string()))?;

        let plaintext = self.service.decrypt_entry(entry, password)?;

        Ok(DecryptResult {
            scope: scope.to_string(),
            description: entry.description.clone(),
            plaintext,
        })
    }

    /// Edit an existing entry.
    pub fn edit_entry(
        &self,
        vault_path: &Path,
        scope: &str,
        new_secret: Option<&str>,
        new_description: Option<&str>,
        password: &str,
    ) -> Result<()> {
        let mut doc = self.service.load_vault(vault_path)?;
        let scope_parts = utils::parse_scope_path(scope);

        // Verify entry exists and password is correct
        let entry = doc
            .find_entry(&scope_parts)
            .ok_or_else(|| VaultError::EntryNotFound(scope.to_string()))?
            .clone();

        // Decrypt to verify password
        let _current = self.service.decrypt_entry(&entry, password)?;

        // Update entry
        self.service.update_entry(
            &mut doc,
            &scope_parts,
            new_secret.map(|s| s.to_string()),
            new_description.map(|s| s.to_string()),
            password,
        )?;

        self.service.save_vault(&doc, vault_path)?;
        Ok(())
    }

    /// Delete an entry.
    pub fn delete_entry(&self, vault_path: &Path, scope: &str) -> Result<()> {
        let mut doc = self.service.load_vault(vault_path)?;
        let scope_parts = utils::parse_scope_path(scope);

        // Check entry exists
        if doc.find_entry(&scope_parts).is_none() {
            return Err(VaultError::EntryNotFound(scope.to_string()));
        }

        // Remove entry
        doc.entries.retain(|e| e.scope_path != scope_parts);

        self.service.save_vault(&doc, vault_path)?;
        Ok(())
    }

    /// Rename an entry.
    pub fn rename_entry(&self, vault_path: &Path, old_scope: &str, new_scope: &str) -> Result<()> {
        let mut doc = self.service.load_vault(vault_path)?;
        let old_parts = utils::parse_scope_path(old_scope);

        self.service
            .rename_entry(&mut doc, &old_parts, new_scope.to_string())?;

        self.service.save_vault(&doc, vault_path)?;
        Ok(())
    }

    /// Get password (always prompts).
    pub fn get_password(
        &self,
        _vault_path: &Path,
        prompt: &str,
        _allow_cache: bool,
    ) -> Result<String> {
        use dialoguer::Password;

        let password = Password::new()
            .with_prompt(prompt)
            .interact()
            .map_err(|e| VaultError::Other(e.to_string()))?;

        if password.is_empty() {
            return Err(VaultError::Cancelled);
        }

        Ok(password)
    }

    /// Handle decryption with display options.
    pub async fn handle_decrypt_display(
        &self,
        result: DecryptResult,
        show_plaintext: bool,
        clipboard: bool,
        no_display: bool,
        timeout: u64,
    ) -> Result<()> {
        let mut plaintext = result.plaintext;

        if no_display {
            // Direct to clipboard without showing
            ClipboardManager::copy_with_timeout(&plaintext, timeout).await?;
            success(&format!(
                "Copied to clipboard (will clear in {timeout} seconds)"
            ));
            success("Secret was not displayed on screen for security");
        } else if clipboard {
            // Copy to clipboard
            ClipboardManager::copy_with_timeout(&plaintext, timeout).await?;
            success(&format!(
                "Copied to clipboard (will clear in {timeout} seconds)"
            ));
        } else if show_plaintext {
            // Interactive display mode
            println!("\n{}", "=".repeat(50));
            println!("{}: {}", "Scope".bold(), result.scope);
            println!("{}: {}", "Description".bold(), result.description);
            println!("{}", "=".repeat(50));

            // Ask user how to display the secret
            print!("\nDisplay the secret in plaintext? [y/N]: ");
            io::stdout().flush()?;

            let mut display_response = String::new();
            io::stdin().read_line(&mut display_response)?;

            if display_response.trim().to_lowercase() == "y" {
                // Display plaintext
                println!(
                    "\n{} Sensitive data displayed below:",
                    "⚠️ Warning:".yellow().bold()
                );
                println!("{}", "=".repeat(50));
                println!("{plaintext}");
                println!("{}", "=".repeat(50));
            } else {
                // Display masked text
                let masked = "*".repeat(plaintext.len());
                println!("\n{} Secret (masked):", "🔒".cyan());
                println!("{}", "=".repeat(50));
                println!("{masked}");
                println!("{}", "=".repeat(50));
                println!("Length: {} characters", plaintext.len());
            }

            // Always ask if user wants to copy to clipboard
            println!();
            print!("Copy to time-locked clipboard (60 seconds)? [y/N]: ");
            io::stdout().flush()?;

            let mut response = String::new();
            io::stdin().read_line(&mut response)?;

            if response.trim().to_lowercase() == "y" {
                ClipboardManager::copy_with_timeout(&plaintext, 60).await?;
                success("Copied to clipboard (will clear in 60 seconds)");
            }

            // Ask to clear screen
            println!();
            print!("Clear screen? [Y/n]: ");
            io::stdout().flush()?;

            let mut clear_response = String::new();
            io::stdin().read_line(&mut clear_response)?;

            if clear_response.trim().to_lowercase() != "n" {
                utils::clear_screen();
                success("Screen cleared");
            }
        }

        // Clear sensitive data
        plaintext.zeroize();
        Ok(())
    }
}

// ============================================================================
// User Story 3: Validation Functions (T091-T095)
// ============================================================================

use crate::models::{ValidationIssue, ValidationReport};
use crate::toml_parser::TomlParser;
use crate::utils::validate_scope_name;
use regex::Regex;

/// Validate a vault file for invalid scopes (T091)
pub fn validate_vault_file(path: &Path) -> Result<ValidationReport> {
    let content = std::fs::read_to_string(path).map_err(VaultError::Io)?;
    let parser = TomlParser::new();

    let mut report = ValidationReport {
        file_path: path.to_path_buf(),
        issues: Vec::new(),
        parse_error: None,
        vault_version: None,
    };

    // Two-phase validation: Try full TOML parse first
    match parser.parse(&content) {
        Ok(doc) => {
            // T092: Full TOML parse succeeded - validate all scopes
            for entry in &doc.entries {
                let scope = entry.scope_string();
                if let Err(VaultError::InvalidScope(err)) = validate_scope_name(&scope) {
                    // Find the line number in the file
                    let line_number = find_scope_line_number(&content, &scope);
                    report.issues.push(ValidationIssue {
                        line_number,
                        scope: scope.clone(),
                        error: err,
                    });
                }
            }
        }
        Err(e) => {
            // T093: TOML parse failed - use regex fallback for best-effort
            report.parse_error = Some(e.to_string());
            scan_for_invalid_scopes(&content, &mut report)?;
        }
    }

    Ok(report)
}

/// Find the line number where a scope appears in the content
fn find_scope_line_number(content: &str, scope: &str) -> usize {
    let section_header = format!("[{scope}]");
    for (idx, line) in content.lines().enumerate() {
        if line.trim() == section_header {
            return idx + 1; // 1-based line numbers
        }
    }
    1 // Default to line 1 if not found
}

/// Scan content for invalid scopes using regex (best-effort when TOML parse fails)
fn scan_for_invalid_scopes(content: &str, report: &mut ValidationReport) -> Result<()> {
    let section_regex = Regex::new(r"\[([^\]]+)\]").unwrap();

    for (line_num, line) in content.lines().enumerate() {
        if let Some(captures) = section_regex.captures(line) {
            let scope = captures.get(1).unwrap().as_str();
            if let Err(VaultError::InvalidScope(err)) = validate_scope_name(scope) {
                report.issues.push(ValidationIssue {
                    line_number: line_num + 1,
                    scope: scope.to_string(),
                    error: err,
                });
            }
        }
    }

    Ok(())
}
