//! Interactive mode for vault operations.

use crate::error::{Result, VaultError};
use crate::security::{ClipboardManager, SessionManager};
use crate::service::VaultService;
use crate::utils::{self, success, warning};
use colored::*;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::path::PathBuf;
use zeroize::Zeroize;

/// Interactive vault shell.
pub struct InteractiveVault {
    vault_path: PathBuf,
    service: VaultService,
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
            service: VaultService::new(),
            editor,
        })
    }

    /// Run the interactive loop.
    pub async fn run(&mut self) -> Result<()> {
        self.print_welcome();

        // Load vault once to verify structure
        self.service.load_vault(&self.vault_path)?;

        loop {
            let prompt = format!("{} ", "vault>".cyan());
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
                    eprintln!("Error: {:?}", err);
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
            "list" | "ls" => self.list_entries(parts.get(1).copied()),
            "add" => {
                if parts.len() < 2 {
                    eprintln!("Usage: add <scope>");
                    Ok(())
                } else {
                    self.add_entry(parts[1]).await
                }
            }
            "show" | "decrypt" => {
                if parts.len() < 2 {
                    eprintln!("Usage: show <scope>");
                    Ok(())
                } else {
                    self.show_entry(parts[1], false).await
                }
            }
            "copy" | "cp" => {
                if parts.len() < 2 {
                    eprintln!("Usage: copy <scope>");
                    Ok(())
                } else {
                    self.show_entry(parts[1], true).await
                }
            }
            "copyq" | "cq" => {
                if parts.len() < 2 {
                    eprintln!("Usage: copyq <scope>");
                    Ok(())
                } else {
                    self.copy_quiet(parts[1]).await
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
            "search" => {
                if parts.len() < 2 {
                    eprintln!("Usage: search <query>");
                    Ok(())
                } else {
                    let query = parts[1..].join(" ");
                    self.search_entries(&query)
                }
            }
            "status" => {
                self.show_status();
                Ok(())
            }
            "lock" => {
                SessionManager::clear_session(&self.vault_path);
                success("Session locked");
                Ok(())
            }
            "exit" | "quit" => {
                self.cleanup();
                std::process::exit(0);
            }
            "clear" => {
                // Clear screen
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
        println!("  {} [filter] - List entries", "list".cyan());
        println!("  {} <scope>  - Add new entry", "add".cyan());
        println!("  {} <scope>  - Show entry", "show".cyan());
        println!("  {} <scope>  - Copy to clipboard", "copy".cyan());
        println!("  {} <scope>  - Copy directly (no display)", "copyq".cyan());
        println!("  {} <scope>  - Edit entry", "edit".cyan());
        println!("  {} <scope> - Delete entry", "delete".cyan());
        println!("  {} <old> <new> - Rename entry", "rename".cyan());
        println!("  {} <query> - Search entries", "search".cyan());
        println!("  {}      - Show session status", "status".cyan());
        println!("  {}        - Lock session", "lock".cyan());
        println!("  {}       - Clear screen", "clear".cyan());
        println!("  {}        - Exit interactive mode", "exit".cyan());
        println!();
        println!("{}", "Security Tips:".bold().cyan());
        println!("  • Secrets are shown with a warning prompt");
        println!("  • You'll be asked to clear screen after viewing");
        println!("  • Clipboard is auto-cleared after 10 seconds");
        println!("  • Use 'clear' command anytime to clear screen");
        println!();
    }

    /// List vault entries.
    fn list_entries(&self, filter: Option<&str>) -> Result<()> {
        let doc = self.service.load_vault(&self.vault_path)?;

        // Get scopes with their encryption status
        let mut scopes_with_status: Vec<(String, bool)> = doc
            .entries
            .iter()
            .map(|e| (e.scope_string(), !e.encrypted_content.trim().is_empty()))
            .collect();

        // Apply filter if provided
        if let Some(prefix) = filter {
            let prefix_parts = utils::parse_scope_path(prefix);
            scopes_with_status.retain(|(s, _)| {
                let parts = utils::parse_scope_path(s);
                parts.len() >= prefix_parts.len() && parts[..prefix_parts.len()] == prefix_parts[..]
            });
        }

        if scopes_with_status.is_empty() {
            println!("No entries found");
        } else {
            println!("\n{}", "Vault Entries:".bold());
            let scopes: Vec<String> = scopes_with_status.iter().map(|(s, _)| s.clone()).collect();
            let tree_lines = utils::format_tree(&scopes);

            for line in tree_lines {
                // Find if this line represents an empty entry
                let is_empty = scopes_with_status
                    .iter()
                    .any(|(scope, has_content)| line.contains(scope) && !*has_content);

                if is_empty {
                    println!("  {} {}", line, "[empty]".yellow());
                } else {
                    println!("  {}", line);
                }
            }
        }

        Ok(())
    }

    /// Add a new entry.
    async fn add_entry(&mut self, scope: &str) -> Result<()> {
        let mut doc = self.service.load_vault(&self.vault_path)?;

        // Get description with placeholder
        print!("Description (e.g., {} credentials): ", scope);
        use std::io::{self, Write};
        io::stdout().flush()?;
        let mut description = String::new();
        io::stdin().read_line(&mut description)?;
        let description = description.trim().to_string();
        let description = if description.is_empty() {
            format!("{} credentials", scope)
        } else {
            description
        };

        // Get password with confirmation for new entries
        let password = self.get_password_with_confirmation()?;

        // Get secret using system editor
        let template = format!(
            "# Enter secret for: {}\n# Lines starting with # will be ignored\n# Save and close the editor when done\n\n",
            scope
        );
        let secret = utils::launch_editor(&template)?;

        // Remove comment lines
        let secret = secret
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");

        if secret.trim().is_empty() {
            return Err(VaultError::NoSecret);
        }

        // Add entry
        self.service
            .add_entry(&mut doc, scope.to_string(), description, secret, &password)?;

        // Save
        self.service.save_vault(&doc, &self.vault_path)?;
        success(&format!("Added: {}", scope));

        // Update session
        SessionManager::update_activity(&self.vault_path);

        Ok(())
    }

    /// Show or copy entry.
    async fn show_entry(&mut self, scope: &str, copy: bool) -> Result<()> {
        let doc = self.service.load_vault(&self.vault_path)?;
        let scope_parts = utils::parse_scope_path(scope);

        let entry = doc
            .find_entry(&scope_parts)
            .ok_or_else(|| VaultError::EntryNotFound(scope.to_string()))?;

        let password = self.get_password(true)?;
        let mut plaintext = self.service.decrypt_entry(entry, &password)?;

        if copy {
            ClipboardManager::copy_with_timeout(&plaintext, 10).await?;
            success("Copied to clipboard (will clear in 10 seconds)");
            plaintext.zeroize();
        } else {
            // Warning before showing
            println!(
                "\n{} Sensitive data will be displayed on screen",
                "⚠️ Warning:".yellow().bold()
            );
            println!("Press Enter to continue or Ctrl+C to cancel...");
            let mut _wait = String::new();
            io::stdin().read_line(&mut _wait)?;

            println!("\n{}", "=".repeat(50));
            println!("{}: {}", "Scope".bold(), scope);
            println!("{}: {}", "Description".bold(), entry.description);
            println!("{}", "=".repeat(50));
            println!("{}", plaintext);
            println!("{}", "=".repeat(50));

            // Ask if user wants to copy to clipboard
            println!();
            print!("Copy to clipboard? [y/N]: ");
            use std::io::{self, Write};
            io::stdout().flush()?;

            let mut response = String::new();
            io::stdin().read_line(&mut response)?;

            if response.trim().to_lowercase() == "y" {
                ClipboardManager::copy_with_timeout(&plaintext, 10).await?;
                success("Copied to clipboard (will clear in 10 seconds)");
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
        }

        // Update session
        SessionManager::update_activity(&self.vault_path);

        Ok(())
    }

    /// Copy entry to clipboard without displaying (secure).
    async fn copy_quiet(&mut self, scope: &str) -> Result<()> {
        let doc = self.service.load_vault(&self.vault_path)?;
        let scope_parts = utils::parse_scope_path(scope);

        let entry = doc
            .find_entry(&scope_parts)
            .ok_or_else(|| VaultError::EntryNotFound(scope.to_string()))?;

        let password = self.get_password(true)?;
        let mut plaintext = self.service.decrypt_entry(entry, &password)?;

        // Copy directly to clipboard without showing
        ClipboardManager::copy_with_timeout(&plaintext, 10).await?;
        success("Copied to clipboard (will clear in 10 seconds)");
        success("Secret was not displayed on screen for security");

        // Clear sensitive data
        plaintext.zeroize();

        // Update session
        SessionManager::update_activity(&self.vault_path);

        Ok(())
    }

    /// Edit an existing entry.
    async fn edit_entry(&mut self, scope: &str) -> Result<()> {
        let mut doc = self.service.load_vault(&self.vault_path)?;
        let scope_parts = utils::parse_scope_path(scope);

        // Check entry exists
        let entry = doc
            .find_entry(&scope_parts)
            .ok_or_else(|| VaultError::EntryNotFound(scope.to_string()))?
            .clone();

        // Get password and decrypt current value
        let password = self.get_password(true)?;
        let _current_secret = self.service.decrypt_entry(&entry, &password)?;

        println!(
            "Editing: {} (press Enter twice to keep current value)",
            scope
        );

        // Get new description
        print!("Description [{}]: ", entry.description);
        use std::io::{self, Write};
        io::stdout().flush()?;
        let mut new_description = String::new();
        io::stdin().read_line(&mut new_description)?;
        let new_description = new_description.trim();
        let new_description = if new_description.is_empty() {
            None
        } else {
            Some(new_description.to_string())
        };

        // Get new secret
        println!("Enter new secret (press Enter twice to keep current):");
        let mut secret_lines = Vec::new();
        let mut empty_count = 0;

        loop {
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;

            if line.trim().is_empty() {
                empty_count += 1;
                if empty_count >= 2 {
                    break;
                }
            } else {
                empty_count = 0;
                secret_lines.push(line.trim_end().to_string());
            }
        }

        let new_secret = if secret_lines.is_empty() {
            None
        } else {
            Some(secret_lines.join("\n"))
        };

        // Update entry
        self.service.update_entry(
            &mut doc,
            &scope_parts,
            new_secret,
            new_description,
            &password,
        )?;

        // Save
        self.service.save_vault(&doc, &self.vault_path)?;
        success(&format!("Updated: {}", scope));

        Ok(())
    }

    /// Delete an entry.
    fn delete_entry(&mut self, scope: &str) -> Result<()> {
        let mut doc = self.service.load_vault(&self.vault_path)?;
        let scope_parts = utils::parse_scope_path(scope);

        // Confirm deletion
        print!("Delete '{}'? (y/N): ", scope);
        use std::io::{self, Write};
        io::stdout().flush()?;
        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm)?;

        if confirm.trim().to_lowercase() != "y" {
            println!("Cancelled");
            return Ok(());
        }

        // Delete
        self.service.delete_entry(&mut doc, &scope_parts)?;
        self.service.save_vault(&doc, &self.vault_path)?;
        success(&format!("Deleted: {}", scope));

        Ok(())
    }

    /// Rename an entry.
    fn rename_entry(&mut self, old_scope: &str, new_scope: &str) -> Result<()> {
        let mut doc = self.service.load_vault(&self.vault_path)?;
        let old_parts = utils::parse_scope_path(old_scope);

        self.service
            .rename_entry(&mut doc, &old_parts, new_scope.to_string())?;
        self.service.save_vault(&doc, &self.vault_path)?;
        success(&format!("Renamed: {} -> {}", old_scope, new_scope));

        Ok(())
    }

    /// Search entries.
    fn search_entries(&self, query: &str) -> Result<()> {
        let doc = self.service.load_vault(&self.vault_path)?;
        let matches = self.service.search_entries(&doc, query, true, false);

        if matches.is_empty() {
            println!("No matches found");
        } else {
            println!("\nFound {} matches:", matches.len());
            for entry in matches {
                println!("  {} - {}", entry.scope_string().cyan(), entry.description);
            }
        }

        Ok(())
    }

    /// Show session status.
    fn show_status(&self) {
        if let Some(session) = SessionManager::get_session(&self.vault_path) {
            let remaining = session.remaining_seconds();
            println!(
                "{}: Active ({} seconds remaining)",
                "Session".bold(),
                remaining
            );
        } else {
            println!("{}: Locked", "Session".bold());
        }
    }

    /// Get password with caching.
    fn get_password(&self, allow_cache: bool) -> Result<String> {
        self.service.get_password_with_session(
            &self.vault_path,
            "Enter vault password",
            allow_cache,
        )
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
        println!("\n{}", "Vault Interactive Mode".bold().cyan());
        println!("Type 'help' for available commands");
        println!("Vault: {}\n", self.vault_path.display());
    }

    /// Cleanup on exit.
    fn cleanup(&self) {
        SessionManager::clear_session(&self.vault_path);
        // Also clean up any temp files we might have created
        let _ = utils::cleanup_old_temp_files();
    }
}

impl Drop for InteractiveVault {
    fn drop(&mut self) {
        // Ensure cleanup happens even on unexpected exit
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_interactive_vault_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let vault_path = temp_file.path().to_path_buf();

        // Create a test vault file
        std::fs::write(&vault_path, "# root <!-- vault-cli v1 -->\n").unwrap();

        // Should fail for non-existent file
        let result = InteractiveVault::new(PathBuf::from("/non/existent/path"));
        assert!(result.is_err());

        // Should succeed for existing file
        let result = InteractiveVault::new(vault_path);
        assert!(result.is_ok());
    }
}
