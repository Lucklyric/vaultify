//! Interactive mode for vault operations.

use crate::error::{Result, VaultError};
use crate::gpg::GpgOperations;
use crate::operations::VaultOperations;
use crate::utils::{self, success, warning};
use colored::*;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::io::{self, Write};
use std::path::PathBuf;

/// Interactive vault shell.
pub struct InteractiveVault {
    vault_path: PathBuf,
    ops: VaultOperations,
    editor: DefaultEditor,
}

impl InteractiveVault {
    /// Create a new interactive vault session.
    pub fn new(vault_path: PathBuf) -> Result<Self> {
        // Check if vault exists
        if !vault_path.exists() {
            return Err(VaultError::VaultNotFound(vault_path));
        }

        // Check permissions
        let warnings = utils::check_file_permissions(&vault_path);
        for warn in warnings {
            warning(&warn);
        }

        let editor = DefaultEditor::new()
            .map_err(|_| VaultError::Other("Failed to create editor".to_string()))?;

        Ok(Self {
            vault_path,
            ops: VaultOperations::new(),
            editor,
        })
    }

    /// Run the interactive loop.
    pub async fn run(&mut self) -> Result<()> {
        self.print_welcome();

        // Load vault once to verify structure
        self.ops.load_vault(&self.vault_path)?;

        // Show help on startup
        self.show_help();

        loop {
            let prompt = format!("{} ", "vaultify>".cyan());
            match self.editor.readline(&prompt) {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    // Add to history
                    let _ = self.editor.add_history_entry(line);

                    // Parse and execute command
                    if let Err(e) = self.execute_command(line).await {
                        eprintln!("{} {}", "Error:".red(), e);
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("\nUse 'exit' to quit");
                }
                Err(ReadlineError::Eof) => {
                    break;
                }
                Err(err) => {
                    eprintln!("Error: {err:?}");
                    break;
                }
            }
        }

        self.cleanup();
        Ok(())
    }

    /// Execute a command.
    async fn execute_command(&mut self, input: &str) -> Result<()> {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        match parts[0] {
            "help" | "?" => {
                self.show_help();
                Ok(())
            }
            "add" => {
                if parts.len() < 2 {
                    eprintln!("Usage: add <scope>");
                    Ok(())
                } else {
                    self.add_entry(parts[1]).await
                }
            }
            "list" | "ls" => self.list_entries(parts.get(1).copied()),
            "decrypt" => {
                if parts.len() < 2 {
                    eprintln!("Usage: decrypt <scope>");
                    Ok(())
                } else {
                    self.decrypt_entry(parts[1]).await
                }
            }
            "edit" => {
                if parts.len() < 2 {
                    eprintln!("Usage: edit <scope>");
                    Ok(())
                } else {
                    self.edit_entry(parts[1]).await
                }
            }
            "delete" | "rm" => {
                if parts.len() < 2 {
                    eprintln!("Usage: delete <scope>");
                    Ok(())
                } else {
                    self.delete_entry(parts[1])
                }
            }
            "rename" | "mv" => {
                if parts.len() < 3 {
                    eprintln!("Usage: rename <old_scope> <new_scope>");
                    Ok(())
                } else {
                    self.rename_entry(parts[1], parts[2])
                }
            }
            "gpg-encrypt" => self.gpg_encrypt_interactive(),
            "gpg-decrypt" => self.gpg_decrypt_interactive(),
            "exit" | "quit" => {
                self.cleanup();
                std::process::exit(0);
            }
            "clear" => {
                utils::clear_screen();
                Ok(())
            }
            _ => {
                eprintln!(
                    "Unknown command: {}. Type 'help' for available commands.",
                    parts[0]
                );
                Ok(())
            }
        }
    }

    /// Show help message.
    fn show_help(&self) {
        println!("\n{}", "Available Commands:".bold());
        println!("  {}        - Show this help", "help".cyan());
        println!("  {} <scope>  - Add new entry", "add".cyan());
        println!(
            "  {} [filter] - List entries (filter searches scope & description)",
            "list".cyan()
        );
        println!("  {} <scope> - Decrypt entry", "decrypt".cyan());
        println!("  {} <scope>  - Edit entry", "edit".cyan());
        println!("  {} <scope> - Delete entry", "delete".cyan());
        println!("  {} <old> <new> - Rename entry", "rename".cyan());
        println!("  {}   - Encrypt vault with GPG", "gpg-encrypt".cyan());
        println!("  {}   - Decrypt GPG-encrypted vault", "gpg-decrypt".cyan());
        println!("  {}       - Clear screen", "clear".cyan());
        println!("  {}        - Exit interactive mode", "exit".cyan());
        println!();
        println!("{}", "Security Tips:".bold().cyan());
        println!("  • Secrets can be displayed or copied to clipboard");
        println!("  • Clipboard is auto-cleared after timeout");
        println!("  • GPG encryption adds an extra security layer");
        println!();
    }

    /// List vault entries.
    fn list_entries(&self, filter: Option<&str>) -> Result<()> {
        let result = self.ops.list_entries(&self.vault_path, filter)?;

        if result.entries.is_empty() {
            println!("No entries found");
        } else {
            // When filtering, show full paths instead of tree
            if filter.is_some() {
                println!("\n{} '{}':", "Entries matching".bold(), filter.unwrap());
                println!();
                for entry in &result.entries {
                    if !entry.has_content {
                        println!(
                            "  {} {} - {}",
                            entry.scope.cyan(),
                            "[empty]".yellow(),
                            entry.description
                        );
                    } else {
                        println!("  {} - {}", entry.scope.cyan(), entry.description);
                    }
                }
            } else {
                // No filter, show as tree
                println!("\n{}", "Vault Entries:".bold());
                let scopes: Vec<String> = result.entries.iter().map(|e| e.scope.clone()).collect();
                let tree_lines = utils::format_tree(&scopes);

                for line in tree_lines {
                    // Find if this line represents an entry
                    if let Some(entry) = result.entries.iter().find(|e| line.contains(&e.scope)) {
                        if !entry.has_content {
                            println!("  {} {} - {}", line, "[empty]".yellow(), entry.description);
                        } else {
                            println!("  {} - {}", line, entry.description);
                        }
                    } else {
                        println!("  {line}");
                    }
                }
            }
        }

        Ok(())
    }

    /// Add a new entry.
    async fn add_entry(&mut self, scope: &str) -> Result<()> {
        // Get description
        print!("Description (e.g., {scope} credentials): ");
        io::stdout().flush()?;
        let mut description = String::new();
        io::stdin().read_line(&mut description)?;
        let description = description.trim().to_string();
        let description = if description.is_empty() {
            format!("{scope} credentials")
        } else {
            description
        };

        // Get password with confirmation
        let password = self.get_password_with_confirmation()?;

        // Get secret value using editor
        println!("Opening editor for secret input...");
        let secret = crate::secure_temp::get_secret_from_editor(None)?;

        // Add entry
        self.ops
            .add_entry(&self.vault_path, scope, &description, &secret, &password)?;
        success(&format!("Added: {scope}"));

        Ok(())
    }

    /// Decrypt and display entry.
    async fn decrypt_entry(&mut self, scope: &str) -> Result<()> {
        // Get password
        let password = self
            .ops
            .get_password(&self.vault_path, "Enter vault password", true)?;

        // Decrypt
        let result = self.ops.decrypt_entry(&self.vault_path, scope, &password)?;

        // Display options
        println!("\n{}", "=".repeat(50));
        println!("{}: {}", "Scope".bold(), result.scope);
        println!("{}: {}", "Description".bold(), result.description);
        println!("{}", "=".repeat(50));

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
            println!("{}", result.plaintext);
            println!("{}", "=".repeat(50));
        } else {
            // Display masked text
            let masked = "*".repeat(result.plaintext.len());
            println!("\n{} Secret (masked):", "🔒".cyan());
            println!("{}", "=".repeat(50));
            println!("{masked}");
            println!("{}", "=".repeat(50));
            println!("Length: {} characters", result.plaintext.len());
        }

        // Always ask if user wants to copy to clipboard
        println!();
        print!("Copy to time-locked clipboard (60 seconds)? [y/N]: ");
        io::stdout().flush()?;

        let mut clipboard_response = String::new();
        io::stdin().read_line(&mut clipboard_response)?;

        if clipboard_response.trim().to_lowercase() == "y" {
            use crate::security::ClipboardManager;
            ClipboardManager::copy_with_timeout(&result.plaintext, 60).await?;
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

        Ok(())
    }

    /// Edit an existing entry.
    async fn edit_entry(&mut self, scope: &str) -> Result<()> {
        // Get password
        let password = self
            .ops
            .get_password(&self.vault_path, "Enter vault password", true)?;

        println!("Editing: {scope} (press Enter to keep current value)");

        // Get new description
        print!("New description (or Enter to keep current): ");
        io::stdout().flush()?;
        let mut new_description = String::new();
        io::stdin().read_line(&mut new_description)?;
        let new_description = new_description.trim();
        let new_description = if new_description.is_empty() {
            None
        } else {
            Some(new_description)
        };

        // Get new secret
        print!("Edit secret? [y/N]: ");
        io::stdout().flush()?;
        let mut edit_response = String::new();
        io::stdin().read_line(&mut edit_response)?;

        let new_secret = if edit_response.trim().to_lowercase() == "y" {
            println!("Opening editor for secret input...");
            Some(crate::secure_temp::get_secret_from_editor(None)?)
        } else {
            None
        };

        // Update entry
        self.ops.edit_entry(
            &self.vault_path,
            scope,
            new_secret.as_deref(),
            new_description,
            &password,
        )?;
        success(&format!("Updated: {scope}"));

        Ok(())
    }

    /// Delete an entry.
    fn delete_entry(&mut self, scope: &str) -> Result<()> {
        // Confirm deletion
        print!("Delete '{scope}'? [y/N]: ");
        io::stdout().flush()?;
        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm)?;

        if confirm.trim().to_lowercase() != "y" {
            println!("Cancelled");
            return Ok(());
        }

        // Delete
        self.ops.delete_entry(&self.vault_path, scope)?;
        success(&format!("Deleted: {scope}"));

        Ok(())
    }

    /// Rename an entry.
    fn rename_entry(&mut self, old_scope: &str, new_scope: &str) -> Result<()> {
        self.ops
            .rename_entry(&self.vault_path, old_scope, new_scope)?;
        success(&format!("Renamed: {old_scope} -> {new_scope}"));
        Ok(())
    }

    /// Get password with confirmation for new entries.
    fn get_password_with_confirmation(&self) -> Result<String> {
        use dialoguer::Password;

        // First password with masked input
        let password = Password::new()
            .with_prompt("Enter password for this secret")
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

    /// Print welcome message.
    fn print_welcome(&self) {
        println!("\n{}", "Vault CLI - Interactive Mode".bold().cyan());
        println!("Type 'help' for available commands");
        println!("Vault: {}", self.vault_path.display());
        println!();
    }

    /// Cleanup on exit.
    fn cleanup(&self) {
        println!("\nGoodbye!");
    }

    /// Encrypt vault file with GPG (interactive).
    fn gpg_encrypt_interactive(&self) -> Result<()> {
        // Ask for encryption options
        print!("Use asymmetric encryption with GPG key? [y/N]: ");
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;

        let recipient = if response.trim().to_lowercase() == "y" {
            // List available keys
            match GpgOperations::list_keys() {
                Ok(keys) if !keys.is_empty() => {
                    println!("\nAvailable GPG keys:");
                    for (i, key) in keys.iter().enumerate() {
                        println!("  {}. {}", i + 1, key);
                    }
                    print!("\nEnter recipient email or key ID: ");
                    io::stdout().flush()?;

                    let mut recipient_input = String::new();
                    io::stdin().read_line(&mut recipient_input)?;
                    Some(recipient_input.trim().to_string())
                }
                _ => {
                    warning("No GPG keys found. Using symmetric encryption.");
                    None
                }
            }
        } else {
            None
        };

        // Ask for ASCII armor
        print!("\nCreate ASCII armored output (.asc)? [y/N]: ");
        io::stdout().flush()?;

        let mut armor_response = String::new();
        io::stdin().read_line(&mut armor_response)?;
        let armor = armor_response.trim().to_lowercase() == "y";

        // Create backup
        let backup_path = GpgOperations::backup_vault(&self.vault_path)?;
        println!("Created backup: {}", backup_path.display());

        // Perform encryption
        let output_path =
            GpgOperations::encrypt_vault(&self.vault_path, recipient.as_deref(), armor)?;

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

    /// Decrypt GPG-encrypted vault file (interactive).
    fn gpg_decrypt_interactive(&self) -> Result<()> {
        // Try to find encrypted vault
        let gpg_path = self.vault_path.with_extension("md.gpg");
        let asc_path = self.vault_path.with_extension("md.asc");

        let encrypted_path = if gpg_path.exists() && asc_path.exists() {
            // Both exist, ask which one to use
            println!("\nFound multiple encrypted files:");
            println!("  1. {}", gpg_path.display());
            println!("  2. {}", asc_path.display());
            print!("\nWhich file to decrypt? [1/2]: ");
            io::stdout().flush()?;

            let mut choice = String::new();
            io::stdin().read_line(&mut choice)?;

            if choice.trim() == "2" {
                asc_path
            } else {
                gpg_path
            }
        } else if gpg_path.exists() {
            gpg_path
        } else if asc_path.exists() {
            asc_path
        } else {
            return Err(VaultError::Other(
                "No encrypted vault file found (vault.md.gpg or vault.md.asc)".to_string(),
            ));
        };

        println!("Decrypting: {}", encrypted_path.display());

        // Check if vault.md already exists
        if self.vault_path.exists() {
            print!(
                "\nWarning: {} already exists. Overwrite? [y/N]: ",
                self.vault_path.display()
            );
            io::stdout().flush()?;

            let mut response = String::new();
            io::stdin().read_line(&mut response)?;

            if response.trim().to_lowercase() != "y" {
                println!("Decryption cancelled.");
                return Ok(());
            }

            // Create backup of existing file
            let backup_path = GpgOperations::backup_vault(&self.vault_path)?;
            println!(
                "Created backup of existing vault: {}",
                backup_path.display()
            );
        }

        // Perform decryption
        let output_path = GpgOperations::decrypt_vault(&encrypted_path, Some(&self.vault_path))?;

        success(&format!(
            "Vault decrypted successfully: {}",
            output_path.display()
        ));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_interactive_vault_creation() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_vault.md");

        // Create a test vault file
        std::fs::write(&vault_path, "# root <!-- vaultify v1 -->\n").unwrap();

        // Create interactive vault
        let vault = InteractiveVault::new(vault_path.clone());
        assert!(vault.is_ok());
    }
}
