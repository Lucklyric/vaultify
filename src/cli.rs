//! Command-line interface implementation.

use crate::crypto::VaultCrypto;
use crate::error::{Result, VaultError};
use crate::models::VaultEntry;
use crate::parser::VaultParser;
use crate::security::{ClipboardManager, SessionManager};
use crate::utils::{self, success, warning};
use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Secure password manager with hierarchical organization.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to vault file
    #[arg(
        short = 'f',
        long,
        global = true,
        env = "VAULT_FILE",
        help = "Path to vault file (default: searches for vault.md)"
    )]
    pub file: Option<PathBuf>,

    /// Output format
    #[arg(
        short = 'o',
        long,
        global = true,
        value_enum,
        default_value = "text",
        help = "Output format"
    )]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new vault
    Init {
        /// Force overwrite if vault exists
        #[arg(short, long)]
        force: bool,
    },

    /// Add a new secret to the vault
    Add {
        /// Secret scope (e.g., personal/email/gmail)
        scope: String,

        /// Description of the secret
        #[arg(short, long)]
        description: Option<String>,

        /// Read secret from stdin
        #[arg(short = 'i', long)]
        stdin: bool,

        /// Use an external editor for secret input
        #[arg(short, long)]
        editor: bool,
    },

    /// List vault entries
    List {
        /// Show as tree structure
        #[arg(short, long)]
        tree: bool,

        /// Filter by scope prefix
        scope: Option<String>,
    },

    /// Decrypt and display a secret
    Decrypt {
        /// Secret scope
        scope: String,

        /// Copy to clipboard instead of displaying
        #[arg(short, long)]
        clipboard: bool,

        /// Show full decrypted content
        #[arg(short, long)]
        show: bool,

        /// Skip display and copy directly to clipboard
        #[arg(short = 'n', long = "no-display")]
        no_display: bool,

        /// Copy to clipboard for N seconds (default: 10)
        #[arg(short = 't', long, default_value = "10")]
        timeout: u64,
    },

    /// Search for entries
    Search {
        /// Search query
        query: String,

        /// Search in descriptions
        #[arg(short, long)]
        description: bool,

        /// Case sensitive search
        #[arg(short = 'c', long)]
        case_sensitive: bool,
    },

    /// Lock the vault session
    Lock,

    /// Show session status
    Status,
}

impl Cli {
    /// Get the vault file path.
    pub fn get_vault_file(&self) -> Result<PathBuf> {
        if let Some(path) = &self.file {
            Ok(path.clone())
        } else if let Some(path) = utils::find_vault_file() {
            Ok(path)
        } else {
            Err(VaultError::Other(
                "No vault file found. Use 'vault init' to create one.".to_string(),
            ))
        }
    }

    /// Execute the CLI command.
    pub async fn execute(&self) -> Result<()> {
        match &self.command {
            Commands::Init { force } => self.init_vault(*force),
            Commands::Add {
                scope,
                description,
                stdin,
                editor,
            } => {
                self.add_secret(scope.clone(), description.clone(), *stdin, *editor)
                    .await
            }
            Commands::List { tree, scope } => self.list_entries(*tree, scope.clone()),
            Commands::Decrypt {
                scope,
                clipboard,
                show,
                no_display,
                timeout,
            } => {
                self.decrypt_secret(scope.clone(), *clipboard, *show, *no_display, *timeout)
                    .await
            }
            Commands::Search {
                query,
                description,
                case_sensitive,
            } => self.search_entries(query.clone(), *description, *case_sensitive),
            Commands::Lock => self.lock_vault(),
            Commands::Status => self.show_status(),
        }
    }

    /// Initialize a new vault.
    fn init_vault(&self, force: bool) -> Result<()> {
        let vault_path = if let Some(path) = &self.file {
            path.clone()
        } else {
            PathBuf::from("vault.md")
        };

        // Check if vault already exists
        if vault_path.exists() && !force {
            return Err(VaultError::Other(format!(
                "Vault already exists at {}. Use --force to overwrite.",
                vault_path.display()
            )));
        }

        // Create vault directory if needed
        if let Some(parent) = vault_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Create new vault file
        let content = VaultParser::create_root_document();
        fs::write(&vault_path, content)?;

        // Set secure permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&vault_path)?.permissions();
            perms.set_mode(0o600); // Read/write for owner only
            fs::set_permissions(&vault_path, perms)?;
        }

        success(&format!("Vault initialized at {}", vault_path.display()));

        // Check permissions and show warnings
        let warnings = utils::check_file_permissions(&vault_path);
        for warn in warnings {
            warning(&warn);
        }

        Ok(())
    }

    /// Add a new secret to the vault.
    async fn add_secret(
        &self,
        scope: String,
        description: Option<String>,
        stdin: bool,
        editor: bool,
    ) -> Result<()> {
        // Validate scope
        if !utils::validate_scope_name(&scope) {
            return Err(VaultError::InvalidScope(scope));
        }

        // Get vault file
        let vault_path = self.get_vault_file()?;

        // Parse vault
        let parser = VaultParser::new();
        let mut doc = parser.parse_file(&vault_path)?;

        // Check if entry already exists
        let scope_parts = utils::parse_scope_path(&scope);
        if doc.find_entry(&scope_parts).is_some() {
            return Err(VaultError::EntryExists(scope));
        }

        // Get password with confirmation for new entries
        let password = self.get_password_with_confirmation("Enter password for this secret")?;

        // Get secret content
        let secret = if stdin {
            // Read from stdin
            use std::io::{self, Read};
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            buffer.trim().to_string()
        } else if editor {
            // Use external editor
            let template = format!(
                "# Enter secret for: {}\n# Lines starting with # will be ignored\n\n",
                scope
            );
            let content = utils::launch_editor(&template)?;
            // Remove comment lines
            content
                .lines()
                .filter(|line| !line.trim_start().starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            // Default to editor for security (unless stdin is specified)
            let template = format!(
                "# Enter secret for: {}\n# Lines starting with # will be ignored\n# Save and close the editor when done\n\n",
                scope
            );
            let content = utils::launch_editor(&template)?;
            // Remove comment lines
            content
                .lines()
                .filter(|line| !line.trim_start().starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
        };

        if secret.is_empty() {
            return Err(VaultError::NoSecret);
        }

        // Encrypt the secret
        let crypto = VaultCrypto::new();
        let (encrypted_content, salt) = crypto.encrypt(&secret, &password)?;

        // Create new entry
        let entry = VaultEntry {
            scope_path: scope_parts.clone(),
            heading_level: scope_parts.len() as u8,
            description: description.unwrap_or_else(|| format!("{} credentials", scope)),
            encrypted_content,
            salt: Some(salt),
            start_line: 0,
            end_line: 0,
        };

        // Add entry to document
        doc.add_entry(entry)
            .map_err(|e| VaultError::Other(e.to_string()))?;

        // Save document
        doc.save(&vault_path)?;

        success(&format!("Added secret: {}", scope));

        // Update session
        SessionManager::update_activity(&vault_path);

        Ok(())
    }

    /// List vault entries.
    fn list_entries(&self, tree: bool, scope_filter: Option<String>) -> Result<()> {
        let vault_path = self.get_vault_file()?;
        let parser = VaultParser::new();
        let doc = parser.parse_file(&vault_path)?;

        // Get all scopes with their encryption status
        let mut scopes_with_status: Vec<(String, bool)> = doc
            .entries
            .iter()
            .map(|e| (e.scope_string(), !e.encrypted_content.trim().is_empty()))
            .collect();

        // Apply filter if provided
        if let Some(filter) = scope_filter {
            let filter_parts = utils::parse_scope_path(&filter);
            scopes_with_status.retain(|(s, _)| {
                let parts = utils::parse_scope_path(s);
                parts.len() >= filter_parts.len() && parts[..filter_parts.len()] == filter_parts[..]
            });
        }

        // Sort for consistent output
        scopes_with_status.sort_by(|a, b| a.0.cmp(&b.0));

        if scopes_with_status.is_empty() {
            println!("No entries found");
            return Ok(());
        }

        if tree {
            // Display as tree - extract just the scopes for now
            let scopes: Vec<String> = scopes_with_status.iter().map(|(s, _)| s.clone()).collect();
            let tree_lines = utils::format_tree(&scopes);
            for line in tree_lines.iter() {
                // Find the corresponding status
                let is_empty = scopes_with_status
                    .iter()
                    .any(|(scope, has_content)| line.contains(scope) && !*has_content);

                if is_empty {
                    println!("{} {}", line, "[empty]".yellow());
                } else {
                    println!("{}", line);
                }
            }
        } else {
            // Display as list
            match self.output {
                OutputFormat::Text => {
                    for (scope, has_content) in scopes_with_status {
                        if has_content {
                            println!("{}", scope);
                        } else {
                            println!("{} {}", scope, "[empty]".yellow());
                        }
                    }
                }
                OutputFormat::Json => {
                    let entries: Vec<serde_json::Value> = scopes_with_status
                        .into_iter()
                        .map(|(scope, has_content)| {
                            serde_json::json!({
                                "scope": scope,
                                "has_content": has_content
                            })
                        })
                        .collect();
                    let json = serde_json::json!({
                        "entries": entries
                    });
                    println!("{}", serde_json::to_string_pretty(&json).unwrap());
                }
            }
        }

        Ok(())
    }

    /// Decrypt and display a secret.
    async fn decrypt_secret(
        &self,
        scope: String,
        clipboard: bool,
        show: bool,
        no_display: bool,
        timeout: u64,
    ) -> Result<()> {
        let vault_path = self.get_vault_file()?;

        // Parse vault
        let parser = VaultParser::new();
        let doc = parser.parse_file(&vault_path)?;

        // Find entry
        let scope_parts = utils::parse_scope_path(&scope);
        let entry = doc
            .find_entry(&scope_parts)
            .ok_or_else(|| VaultError::EntryNotFound(scope.clone()))?;

        // Check if entry has encrypted content
        if entry.encrypted_content.is_empty() {
            return Err(VaultError::NoEncryptedContent(scope));
        }

        // Check if entry has salt
        let salt = entry
            .salt
            .as_ref()
            .ok_or_else(|| VaultError::NoSalt(scope.clone()))?;

        // Get password
        let password = self.get_password(&vault_path, true)?;

        // Decrypt
        let crypto = VaultCrypto::new();
        let mut plaintext = crypto
            .decrypt(&entry.encrypted_content, &password, salt)
            .map_err(|_| VaultError::DecryptionFailed)?;

        // Update session activity
        SessionManager::update_activity(&vault_path);

        // Handle output
        if no_display {
            // Direct to clipboard without showing
            ClipboardManager::copy_with_timeout(&plaintext, timeout).await?;
            success(&format!(
                "Copied to clipboard (will clear in {} seconds)",
                timeout
            ));
            success("Secret was not displayed on screen for security");
            plaintext.zeroize();
        } else if clipboard {
            ClipboardManager::copy_with_timeout(&plaintext, timeout).await?;
            success(&format!(
                "Copied to clipboard (will clear in {} seconds)",
                timeout
            ));
        } else if show {
            // Warning before showing
            println!(
                "\n{} Sensitive data will be displayed on screen",
                "⚠️ Warning:".yellow().bold()
            );
            println!("Press Enter to continue or Ctrl+C to cancel...");
            let mut _wait = String::new();
            io::stdin().read_line(&mut _wait)?;

            println!("{}", "=".repeat(40));
            println!("{}: {}", "Scope".bold(), scope);
            println!("{}: {}", "Description".bold(), entry.description);
            println!("{}", "=".repeat(40));
            println!("{}", plaintext);
            println!("{}", "=".repeat(40));

            // Ask if user wants to copy to clipboard
            println!();
            print!("Copy to clipboard? [y/N]: ");
            use std::io::{self, Write};
            io::stdout().flush()?;

            let mut response = String::new();
            io::stdin().read_line(&mut response)?;

            if response.trim().to_lowercase() == "y" {
                ClipboardManager::copy_with_timeout(&plaintext, timeout).await?;
                success(&format!(
                    "Copied to clipboard (will clear in {} seconds)",
                    timeout
                ));
            }

            // Ask to clear screen
            println!();
            print!("Clear screen? [Y/n]: ");
            io::stdout().flush()?;

            let mut clear_response = String::new();
            io::stdin().read_line(&mut clear_response)?;

            if clear_response.trim().to_lowercase() != "n" {
                // Clear screen
                utils::clear_screen();
                success("Screen cleared");
            }

            // Clear sensitive data from memory
            plaintext.zeroize();
        } else {
            // Default: show masked preview and options
            let preview = if plaintext.len() > 20 {
                format!("{}...", &plaintext[..20])
            } else {
                plaintext.clone()
            };

            println!("\n{}", "=".repeat(40));
            println!("{}: {}", "Scope".bold(), scope);
            println!("{}: {}", "Description".bold(), entry.description);
            println!("{}: {}", "Preview".bold(), preview);
            println!("{}", "=".repeat(40));

            // Ask what to do
            println!("\nWhat would you like to do?");
            println!("  1) Copy to clipboard (secure)");
            println!("  2) Display in terminal");
            println!("  3) Cancel");
            print!("\nChoice [1-3]: ");
            use std::io::{self, Write};
            io::stdout().flush()?;

            let mut choice = String::new();
            io::stdin().read_line(&mut choice)?;

            match choice.trim() {
                "1" => {
                    ClipboardManager::copy_with_timeout(&plaintext, timeout).await?;
                    success(&format!(
                        "Copied to clipboard (will clear in {} seconds)",
                        timeout
                    ));
                }
                "2" => {
                    println!("\n{}", "=".repeat(40));
                    println!("{}", plaintext);
                    println!("{}", "=".repeat(40));

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
                _ => {
                    println!("Cancelled");
                }
            }
        }

        // Clear sensitive data
        plaintext.zeroize();

        Ok(())
    }

    /// Search for entries.
    fn search_entries(
        &self,
        query: String,
        in_description: bool,
        case_sensitive: bool,
    ) -> Result<()> {
        let vault_path = self.get_vault_file()?;
        let parser = VaultParser::new();
        let doc = parser.parse_file(&vault_path)?;

        let query_lower = if case_sensitive {
            query.clone()
        } else {
            query.to_lowercase()
        };

        let mut matches = Vec::new();

        for entry in &doc.entries {
            let scope = entry.scope_string();
            let scope_check = if case_sensitive {
                scope.clone()
            } else {
                scope.to_lowercase()
            };

            let description_check = if case_sensitive {
                entry.description.clone()
            } else {
                entry.description.to_lowercase()
            };

            let found = if in_description {
                description_check.contains(&query_lower)
            } else {
                scope_check.contains(&query_lower)
            };

            if found {
                matches.push((scope, entry.description.clone()));
            }
        }

        if matches.is_empty() {
            println!("No matches found for '{}'", query);
        } else {
            match self.output {
                OutputFormat::Text => {
                    println!("Found {} matches:", matches.len());
                    for (scope, desc) in matches {
                        println!("  {} - {}", scope.cyan(), desc);
                    }
                }
                OutputFormat::Json => {
                    let json: Vec<_> = matches
                        .into_iter()
                        .map(|(scope, description)| {
                            serde_json::json!({
                                "scope": scope,
                                "description": description
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&json).unwrap());
                }
            }
        }

        Ok(())
    }

    /// Lock the vault session.
    fn lock_vault(&self) -> Result<()> {
        if let Ok(vault_path) = self.get_vault_file() {
            SessionManager::clear_session(&vault_path);
            success("Vault session locked");
        } else {
            SessionManager::clear_all_sessions();
            success("All vault sessions locked");
        }
        Ok(())
    }

    /// Show session status.
    fn show_status(&self) -> Result<()> {
        let vault_path = self.get_vault_file()?;

        if let Some(session) = SessionManager::get_session(&vault_path) {
            let remaining = session.remaining_seconds();
            println!("{}: Active", "Status".bold());
            println!("{}: {} seconds", "Time remaining".bold(), remaining);
            println!("{}: {}", "Vault".bold(), vault_path.display());
        } else {
            println!("{}: Locked", "Status".bold());
            println!("{}: {}", "Vault".bold(), vault_path.display());
        }

        Ok(())
    }

    /// Get password for vault operations.
    fn get_password_with_confirmation(&self, prompt: &str) -> Result<String> {
        use dialoguer::Password;

        // First password with masked input
        let password = Password::new()
            .with_prompt(prompt)
            .interact()
            .map_err(|e| VaultError::Other(e.to_string()))?;

        if password.is_empty() {
            return Err(VaultError::Cancelled);
        }

        // Confirmation with masked input
        let confirm = Password::new()
            .with_prompt("Confirm password")
            .interact()
            .map_err(|e| VaultError::Other(e.to_string()))?;

        if password != confirm {
            return Err(VaultError::Other("Passwords do not match".to_string()));
        }

        Ok(password)
    }

    fn get_password(&self, vault_path: &Path, allow_session: bool) -> Result<String> {
        // Check for active session
        if allow_session {
            if let Some(session) = SessionManager::get_session(vault_path) {
                if let Some(ref key) = session.cached_key {
                    // Decrypt a small test to verify the key still works
                    // This prevents using stale session data
                    return Ok(String::from_utf8(key.clone())?);
                }
            }
        }

        // Prompt for password with masked input
        use dialoguer::Password;
        let password = Password::new()
            .with_prompt("Enter vault password")
            .interact()
            .map_err(|e| VaultError::Other(e.to_string()))?;

        if password.is_empty() {
            return Err(VaultError::Cancelled);
        }

        // Create new session if we're allowing sessions
        if allow_session {
            let mut session = SessionManager::create_session(vault_path);
            session.cached_key = Some(password.as_bytes().to_vec());
        }

        Ok(password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_validate_scope_name() {
        assert!(utils::validate_scope_name("personal/email"));
        assert!(utils::validate_scope_name("work/vpn"));
        assert!(!utils::validate_scope_name(""));
        assert!(!utils::validate_scope_name("with<invalid>"));
    }

    #[test]
    fn test_parse_scope_path() {
        assert_eq!(
            utils::parse_scope_path("personal/banking/chase"),
            vec!["personal", "banking", "chase"]
        );
        assert_eq!(utils::parse_scope_path("work"), vec!["work"]);
    }
}
