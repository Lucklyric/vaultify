//! Utility functions for vault operations.

use crate::error::{Result, VaultError};
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Parse a scope path string into components.
pub fn parse_scope_path(scope: &str) -> Vec<String> {
    scope
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Format a scope path as a string.
pub fn format_scope_path(parts: &[String]) -> String {
    parts.join("/")
}

/// Validate a scope name.
pub fn validate_scope_name(scope: &str) -> bool {
    if scope.is_empty() {
        return false;
    }

    // Check for invalid characters
    let invalid_chars = ['<', '>', '|', '\\', '\n', '\t', '\r'];
    if scope.chars().any(|c| invalid_chars.contains(&c)) {
        return false;
    }

    // Check each part
    for part in scope.split('/') {
        if part.is_empty() {
            continue;
        }

        // Don't allow . or .. as entire part
        if part == "." || part == ".." {
            return false;
        }

        // First character restrictions
        if let Some(first) = part.chars().next() {
            if first == '-' || first == '_' {
                return false;
            }
        }
    }

    true
}

/// Find a vault file in the current directory or parents.
pub fn find_vault_file() -> Option<PathBuf> {
    let current_dir = std::env::current_dir().ok()?;

    // Check current directory
    for name in &["vault.md", ".vault.md", "credentials.md"] {
        let path = current_dir.join(name);
        if path.exists() {
            return Some(path);
        }
    }

    // Check parent directories
    let mut dir = current_dir.parent();
    while let Some(parent) = dir {
        for name in &["vault.md", ".vault.md", "credentials.md"] {
            let path = parent.join(name);
            if path.exists() {
                return Some(path);
            }
        }
        dir = parent.parent();
    }

    None
}

/// Check file permissions and return warnings.
pub fn check_file_permissions(path: &Path) -> Vec<String> {
    let mut warnings = Vec::new();

    #[cfg(unix)]
    {
        if let Ok(metadata) = fs::metadata(path) {
            let permissions = metadata.permissions();
            let mode = permissions.mode();

            // Check if group or others have any permissions
            if mode & 0o077 != 0 {
                warnings.push(format!(
                    "File has insecure permissions: {:o}. Run 'chmod 600 {}' to fix.",
                    mode & 0o777,
                    path.display()
                ));
            }
        }
    }

    warnings
}

/// Get multiline input securely in-memory without temp files.
pub fn get_multiline_input(prompt: &str) -> Result<String> {
    use std::io;

    println!("{prompt}");
    println!("Enter your text (press Ctrl+D or type 'EOF' on a new line to finish):");
    println!("{}", "-".repeat(50));

    let mut lines = Vec::new();
    let stdin = io::stdin();
    let mut input = String::new();

    loop {
        input.clear();
        match stdin.read_line(&mut input) {
            Ok(0) => break, // EOF (Ctrl+D)
            Ok(_) => {
                let trimmed = input.trim_end();
                if trimmed == "EOF" {
                    break;
                }
                lines.push(trimmed.to_string());
            }
            Err(e) => return Err(VaultError::Io(e)),
        }
    }

    Ok(lines.join("\n"))
}

/// Launch editor for secret input.
pub fn launch_editor(template: &str) -> Result<String> {
    use tempfile::NamedTempFile;

    // Create temporary file with restrictive permissions
    let temp_file = NamedTempFile::new()?;
    let temp_path = temp_file.path().to_path_buf();

    // Set secure permissions on temp file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&temp_path, permissions)?;
    }

    fs::write(&temp_path, template)?;

    // Get editor from environment
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());

    // Launch editor
    let status = Command::new(&editor)
        .arg(&temp_path)
        .status()
        .map_err(|_| VaultError::EditorFailed)?;

    if !status.success() {
        // Overwrite with zeros before deletion
        if let Ok(file_size) = fs::metadata(&temp_path).map(|m| m.len()) {
            let zeros = vec![0u8; file_size as usize];
            let _ = fs::write(&temp_path, zeros);
        }
        // Ensure temp file is cleaned up on cancel
        let _ = temp_file.close();
        return Err(VaultError::Cancelled);
    }

    // Read content
    let content = match fs::read_to_string(&temp_path) {
        Ok(c) => c,
        Err(e) => {
            // Clean up on error
            if let Ok(file_size) = fs::metadata(&temp_path).map(|m| m.len()) {
                let zeros = vec![0u8; file_size as usize];
                let _ = fs::write(&temp_path, zeros);
            }
            let _ = temp_file.close();
            return Err(VaultError::Io(e));
        }
    };

    // Overwrite file with zeros before closing
    let zeros = vec![0u8; content.len().max(1024)]; // At least 1KB of zeros
    let _ = fs::write(&temp_path, zeros);

    // Close and delete temp file
    let _ = temp_file.close();

    Ok(content)
}

/// Format a tree structure for display.
pub fn format_tree(scopes: &[String]) -> Vec<String> {
    if scopes.is_empty() {
        return vec!["(empty)".to_string()];
    }

    let mut lines = Vec::new();
    let mut last_parts: Vec<String> = Vec::new();

    for (i, scope) in scopes.iter().enumerate() {
        let parts: Vec<&str> = scope.split('/').collect();
        let level = parts.len() - 1;
        let is_last = i == scopes.len() - 1 || {
            // Check if this is the last item at its level
            if i + 1 < scopes.len() {
                let next_parts: Vec<&str> = scopes[i + 1].split('/').collect();
                next_parts.len() <= parts.len() || next_parts[..level] != parts[..level]
            } else {
                true
            }
        };

        let mut prefix = String::new();
        for j in 0..level {
            if j < last_parts.len() && last_parts[j] == "│" {
                prefix.push_str("│   ");
            } else {
                prefix.push_str("    ");
            }
        }

        if level > 0 {
            if is_last {
                prefix.push_str("└── ");
            } else {
                prefix.push_str("├── ");
            }
        }

        let item_name = parts.last().unwrap_or(&"");
        lines.push(format!("{prefix}{item_name}"));

        // Update last_parts for next iteration
        last_parts.clear();
        for j in 0..level {
            if j < parts.len() - 1 {
                last_parts.push(if is_last { " " } else { "│" }.to_string());
            }
        }
    }

    lines
}

/// Print an error message and exit.
pub fn error_exit(message: &str, code: i32) -> ! {
    eprintln!("{} {}", "Error:".red().bold(), message);
    std::process::exit(code);
}

/// Print a success message.
pub fn success(message: &str) {
    println!("{} {}", "✓".green(), message);
}

/// Clear the terminal screen.
pub fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
    use std::io::{self, Write};
    let _ = io::stdout().flush();
}

/// Print a warning message.
pub fn warning(message: &str) {
    println!("{} {}", "Warning:".yellow(), message);
}

/// Clean up old vault temp files from previous sessions.
pub fn cleanup_old_temp_files() -> Result<()> {
    use std::time::SystemTime;

    // Get temp directory
    let temp_dir = std::env::temp_dir();

    // Look for vault temp files (files that match our naming pattern)
    // tempfile creates files with specific patterns, but we'll look for any temp files
    // that might contain vault data based on common patterns
    let mut cleaned_count = 0;

    if let Ok(entries) = fs::read_dir(&temp_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Check if this looks like a vault temp file
            // tempfile uses patterns like ".tmp" followed by random chars
            // We'll also check for files that might contain "vault" or "secret" in the name
            let is_likely_vault_temp = (file_name.starts_with(".tmp") && file_name.len() > 10)
                || file_name.contains("vault") && file_name.contains("tmp")
                || file_name.contains("secret") && file_name.contains("tmp");

            if is_likely_vault_temp && path.is_file() {
                // Check file age - only remove files older than 1 hour
                if let Ok(metadata) = fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                            // If file is older than 1 hour, it's likely abandoned
                            if elapsed.as_secs() > 3600 {
                                // Try to read first few bytes to see if it looks like vault content
                                if let Ok(content) = fs::read_to_string(&path) {
                                    // Check if it contains patterns that suggest it's a vault editor file
                                    if content.contains("# Enter secret")
                                        || content.contains("# Lines starting with #")
                                        || content.contains("credentials")
                                    {
                                        // Overwrite with zeros before deletion
                                        let file_size = metadata.len();
                                        let zeros = vec![0u8; file_size as usize];
                                        let _ = fs::write(&path, zeros);

                                        // Delete the file
                                        if fs::remove_file(&path).is_ok() {
                                            cleaned_count += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if cleaned_count > 0 {
        // Don't display this to avoid cluttering the UI
        // Just silently clean up
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scope_path() {
        assert_eq!(
            parse_scope_path("personal/banking/chase"),
            vec!["personal", "banking", "chase"]
        );
        assert_eq!(parse_scope_path("/personal/"), vec!["personal"]);
        assert_eq!(parse_scope_path(""), Vec::<String>::new());
    }

    #[test]
    fn test_validate_scope_name() {
        assert!(validate_scope_name("personal/banking"));
        assert!(validate_scope_name("work-stuff"));
        assert!(validate_scope_name("test_123"));

        assert!(!validate_scope_name(""));
        assert!(!validate_scope_name("with<angle>"));
        assert!(!validate_scope_name("with|pipe"));
        assert!(!validate_scope_name("personal/."));
        assert!(!validate_scope_name("personal/.."));
    }

    #[test]
    fn test_format_tree() {
        let scopes = vec![
            "personal".to_string(),
            "personal/banking".to_string(),
            "personal/banking/chase".to_string(),
            "personal/email".to_string(),
            "work".to_string(),
        ];

        let tree = format_tree(&scopes);
        assert_eq!(tree.len(), 5);
        assert_eq!(tree[0], "personal");
        assert!(tree[1].contains("├── banking"));
        assert!(tree[2].contains("└── chase"));
        assert!(tree[3].contains("└── email"));
        assert_eq!(tree[4], "work");
    }
}
