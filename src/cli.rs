//! Command-line interface implementation.

use crate::error::{Result, VaultError};
use crate::gpg::GpgOperations;
use crate::operations::VaultOperations;
use crate::utils::{self, success};
use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

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
        help = "Path to vault file (default: searches for vault.toml)"
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
        #[arg(long)]
        force: bool,
    },

    /// Add a new secret to the vault
    Add {
        /// Secret scope (e.g., personal.email.gmail)
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

        /// Filter entries (searches in both scope and description)
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

        /// Copy to clipboard for N seconds (default: 60)
        #[arg(short = 't', long, default_value = "60")]
        timeout: u64,
    },

    /// Edit an existing entry
    Edit {
        /// Secret scope
        scope: String,

        /// New description
        #[arg(short, long)]
        description: Option<String>,

        /// Use an external editor for secret input
        #[arg(short, long)]
        editor: bool,

        /// Edit description interactively (multiline)
        #[arg(long)]
        edit_description: bool,
    },

    /// Delete an entry
    Delete {
        /// Secret scope
        scope: String,

        /// Force deletion without confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// Rename an entry
    Rename {
        /// Current scope
        old_scope: String,

        /// New scope
        new_scope: String,
    },

    /// Encrypt vault file with GPG
    GpgEncrypt {
        /// GPG recipient for asymmetric encryption (optional)
        #[arg(short, long)]
        recipient: Option<String>,

        /// Output ASCII armored format
        #[arg(short, long)]
        armor: bool,

        /// Create backup before encryption
        #[arg(short, long, default_value = "false")]
        backup: bool,
    },

    /// Decrypt GPG-encrypted vault file
    GpgDecrypt {
        /// Input file (default: vault.toml.gpg or vault.toml.asc)
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Output file (default: vault.toml)
        #[arg(short = 'O', long = "output-file")]
        output_file: Option<PathBuf>,
    },
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
            Commands::Edit {
                scope,
                description,
                editor,
                edit_description,
            } => {
                self.edit_entry(
                    scope.clone(),
                    description.clone(),
                    *editor,
                    *edit_description,
                )
                .await
            }
            Commands::Delete { scope, force } => self.delete_entry(scope.clone(), *force),
            Commands::Rename {
                old_scope,
                new_scope,
            } => self.rename_entry(old_scope.clone(), new_scope.clone()),
            Commands::GpgEncrypt {
                recipient,
                armor,
                backup,
            } => self.gpg_encrypt(recipient.as_deref(), *armor, *backup),
            Commands::GpgDecrypt { input, output_file } => {
                self.gpg_decrypt(input.as_deref(), output_file.as_deref())
            }
        }
    }

    /// Initialize a new vault.
    fn init_vault(&self, force: bool) -> Result<()> {
        let vault_path = if let Some(path) = &self.file {
            path.clone()
        } else {
            PathBuf::from("vault.toml")
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
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        // Create vault file with TOML format
        let content = "version = \"v0.3\"\ncreated = \"{}\"\n";
        let now = chrono::Utc::now().to_rfc3339();
        fs::write(&vault_path, content.replace("{}", &now))?;

        // Set proper permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&vault_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&vault_path, perms)?;
        }

        success(&format!("Vault initialized at {}", vault_path.display()));
        Ok(())
    }

    /// Add a new secret.
    async fn add_secret(
        &self,
        scope: String,
        description: Option<String>,
        stdin: bool,
        editor: bool,
    ) -> Result<()> {
        let vault_path = self.get_vault_file()?;
        let ops = VaultOperations::new();

        // Get description
        let description = if let Some(desc) = description {
            desc
        } else {
            self.get_multiline_description()?
        };

        // Get secret
        let secret = if stdin {
            let mut secret = String::new();
            io::stdin().read_line(&mut secret)?;
            secret.trim().to_string()
        } else if editor {
            self.get_secret_from_editor()?
        } else {
            self.get_secret_interactively()?
        };

        // Get password
        let password = self.get_password_with_confirmation("Enter password for this secret")?;

        // Add entry
        ops.add_entry(&vault_path, &scope, &description, &secret, &password)?;

        success(&format!("Added: {scope}"));
        Ok(())
    }

    /// List vault entries.
    fn list_entries(&self, tree: bool, scope_filter: Option<String>) -> Result<()> {
        let vault_path = self.get_vault_file()?;
        let ops = VaultOperations::new();
        let result = ops.list_entries(&vault_path, scope_filter.as_deref())?;

        if result.entries.is_empty() {
            println!("No entries found");
            return Ok(());
        }

        // When filtering, always show full paths for clarity
        let use_tree = tree && scope_filter.is_none();

        if use_tree {
            // Display as tree with descriptions
            let scopes: Vec<String> = result.entries.iter().map(|e| e.scope.clone()).collect();
            let tree_lines = utils::format_tree(&scopes);

            for (i, line) in tree_lines.iter().enumerate() {
                // Find the corresponding entry by matching the scope from the original scopes list
                if i < scopes.len() {
                    if let Some(entry) = result.entries.iter().find(|e| e.scope == scopes[i]) {
                        let desc_lines: Vec<&str> = entry.description.lines().collect();
                        let first_line = desc_lines.first().copied().unwrap_or("");

                        if !entry.has_content {
                            println!("{} {} - {}", line, "[empty]".yellow(), first_line);
                        } else {
                            println!("{} - {}", line, first_line);
                        }

                        // Print additional description lines with appropriate indentation
                        if desc_lines.len() > 1 {
                            // Calculate indentation based on tree line
                            let indent_len = line.len() + 3; // +3 for " - "
                            let indent = " ".repeat(indent_len);
                            for desc_line in desc_lines.iter().skip(1) {
                                println!("{}{}", indent, desc_line);
                            }
                        }
                    } else {
                        println!("{line}");
                    }
                }
            }
        } else {
            // Display as list with full paths
            match self.output {
                OutputFormat::Text => {
                    // If filtering, show a header
                    if let Some(ref filter) = scope_filter {
                        println!("Entries matching '{filter}':");
                        println!();
                    }

                    for entry in &result.entries {
                        // Format multiline descriptions
                        let desc_lines: Vec<&str> = entry.description.lines().collect();
                        let first_line = desc_lines.first().copied().unwrap_or("");

                        if entry.has_content {
                            println!("{} - {}", entry.scope.cyan(), first_line);
                        } else {
                            println!(
                                "{} {} - {}",
                                entry.scope.cyan(),
                                "[empty]".yellow(),
                                first_line
                            );
                        }

                        // Print additional description lines indented
                        for line in desc_lines.iter().skip(1) {
                            println!("  {}", line);
                        }
                    }
                }
                OutputFormat::Json => {
                    let entries: Vec<serde_json::Value> = result
                        .entries
                        .into_iter()
                        .map(|entry| {
                            serde_json::json!({
                                "scope": entry.scope,
                                "has_content": entry.has_content,
                                "description": entry.description
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
        let ops = VaultOperations::new();

        // Get password
        let password = ops.get_password(&vault_path, "Enter vault password", true)?;

        // Decrypt entry
        let result = ops.decrypt_entry(&vault_path, &scope, &password)?;

        // Handle display
        ops.handle_decrypt_display(result, show, clipboard, no_display, timeout)
            .await?;

        Ok(())
    }

    /// Edit an existing entry.
    async fn edit_entry(
        &self,
        scope: String,
        description: Option<String>,
        editor: bool,
        edit_description: bool,
    ) -> Result<()> {
        let vault_path = self.get_vault_file()?;
        let ops = VaultOperations::new();

        // Get password
        let password = ops.get_password(&vault_path, "Enter vault password", true)?;

        // Get new description if requested
        let final_description = if edit_description {
            Some(self.get_multiline_description()?)
        } else {
            description
        };

        // Get new secret if editing
        let new_secret = if editor {
            Some(self.get_secret_from_editor()?)
        } else {
            print!("Enter new secret (or press Enter to keep current): ");
            io::stdout().flush()?;
            let mut secret = String::new();
            io::stdin().read_line(&mut secret)?;
            let secret = secret.trim();
            if secret.is_empty() {
                None
            } else {
                Some(secret.to_string())
            }
        };

        // Edit entry
        ops.edit_entry(
            &vault_path,
            &scope,
            new_secret.as_deref(),
            final_description.as_deref(),
            &password,
        )?;

        success(&format!("Updated: {scope}"));
        Ok(())
    }

    /// Delete an entry.
    fn delete_entry(&self, scope: String, force: bool) -> Result<()> {
        let vault_path = self.get_vault_file()?;
        let ops = VaultOperations::new();

        // Confirm deletion
        if !force {
            print!("Delete '{scope}'? [y/N]: ");
            io::stdout().flush()?;
            let mut confirm = String::new();
            io::stdin().read_line(&mut confirm)?;

            if confirm.trim().to_lowercase() != "y" {
                println!("Cancelled");
                return Ok(());
            }
        }

        // Delete entry
        ops.delete_entry(&vault_path, &scope)?;

        success(&format!("Deleted: {scope}"));
        Ok(())
    }

    /// Rename an entry.
    fn rename_entry(&self, old_scope: String, new_scope: String) -> Result<()> {
        let vault_path = self.get_vault_file()?;
        let ops = VaultOperations::new();

        // Rename entry
        ops.rename_entry(&vault_path, &old_scope, &new_scope)?;

        success(&format!("Renamed: {old_scope} -> {new_scope}"));
        Ok(())
    }

    /// Encrypt vault file with GPG.
    fn gpg_encrypt(&self, recipient: Option<&str>, armor: bool, backup: bool) -> Result<()> {
        let vault_path = self.get_vault_file()?;

        // Ask about backup interactively if not specified via CLI flag
        let should_backup = if backup {
            true
        } else {
            print!("Create backup before encryption? [y/N]: ");
            io::stdout().flush()?;
            let mut response = String::new();
            io::stdin().read_line(&mut response)?;
            response.trim().to_lowercase() == "y"
        };

        // Create backup if requested
        if should_backup {
            let backup_path = GpgOperations::backup_vault(&vault_path)?;
            println!("Created backup: {}", backup_path.display());
        }

        // Perform encryption
        let output_path = GpgOperations::encrypt_vault(&vault_path, recipient, armor)?;

        success(&format!(
            "Vault encrypted successfully: {}",
            output_path.display()
        ));

        if recipient.is_some() {
            println!("Encrypted for recipient: {}", recipient.unwrap());
        } else {
            println!("Encrypted with symmetric key (password-based)");
        }

        Ok(())
    }

    /// Decrypt GPG-encrypted vault file.
    fn gpg_decrypt(&self, input: Option<&Path>, output: Option<&Path>) -> Result<()> {
        // Determine input file
        let encrypted_path = if let Some(path) = input {
            path.to_path_buf()
        } else {
            // Try to find encrypted vault
            let vault_path = self.get_vault_file()?;
            let gpg_path = vault_path.with_extension("toml.gpg");
            let asc_path = vault_path.with_extension("toml.asc");

            if gpg_path.exists() {
                gpg_path
            } else if asc_path.exists() {
                asc_path
            } else {
                return Err(VaultError::Other(
                    "No encrypted vault file found (vault.toml.gpg or vault.toml.asc)".to_string(),
                ));
            }
        };

        // Perform decryption
        let output_path = GpgOperations::decrypt_vault(&encrypted_path, output)?;

        success(&format!(
            "Vault decrypted successfully: {}",
            output_path.display()
        ));

        Ok(())
    }

    /// Get password with confirmation for new entries.
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

    /// Get secret interactively using the system editor.
    fn get_secret_interactively(&self) -> Result<String> {
        println!("Opening editor for secret input...");
        crate::secure_temp::get_secret_from_editor(None)
    }

    /// Get secret from external editor (delegates to secure_temp).
    fn get_secret_from_editor(&self) -> Result<String> {
        crate::secure_temp::get_secret_from_editor(None)
    }

    /// Get multiline description interactively.
    fn get_multiline_description(&self) -> Result<String> {
        println!("Enter description (press Enter twice to finish):");

        let mut lines = Vec::new();
        let mut empty_line_count = 0;

        loop {
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;

            if line.trim().is_empty() {
                empty_line_count += 1;
                if empty_line_count >= 2 {
                    break;
                }
                lines.push(String::new());
            } else {
                empty_line_count = 0;
                lines.push(line.trim_end().to_string());
            }
        }

        // Remove trailing empty lines
        while lines.last().map(|s| s.is_empty()).unwrap_or(false) {
            lines.pop();
        }

        Ok(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_scope_name() {
        assert!(utils::validate_scope_name("personal.email"));
        assert!(utils::validate_scope_name("work.vpn"));
        assert!(!utils::validate_scope_name(""));
        assert!(!utils::validate_scope_name("personal.."));
        assert!(!utils::validate_scope_name("personal..."));
        assert!(!utils::validate_scope_name(".personal"));
        assert!(!utils::validate_scope_name("personal."));
    }

    #[test]
    fn test_parse_scope_path() {
        let parts = utils::parse_scope_path("personal.email.gmail");
        assert_eq!(parts, vec!["personal", "email", "gmail"]);
    }
}
