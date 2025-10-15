//! Utility functions for vault operations.

use crate::error::{Result, ScopeValidationError, ValidationErrorKind, VaultError};
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Unicode whitespace characters to reject
const UNICODE_WHITESPACE: &[char] = &[
    '\u{00A0}', // NO-BREAK SPACE
    '\u{2003}', // EM SPACE
    '\u{2009}', // THIN SPACE
    '\u{200A}', // HAIR SPACE
    '\u{202F}', // NARROW NO-BREAK SPACE
];

/// Check if character is valid in scope names
fn is_valid_scope_char(ch: char) -> bool {
    matches!(ch, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '-' | '_')
}

/// Check if character is Unicode whitespace variant
fn is_unicode_whitespace(ch: char) -> bool {
    UNICODE_WHITESPACE.contains(&ch)
}

/// Calculate 1-based character position from byte index
fn char_position_from_byte_index(input: &str, byte_index: usize) -> usize {
    input[..byte_index].chars().count() + 1
}

/// Validate that a scope part doesn't have invalid boundaries
fn validate_part_boundaries(part: &str, part_start_pos: usize) -> Result<()> {
    if part.starts_with('-') {
        return Err(ScopeValidationError::new(
            part,
            ValidationErrorKind::HyphenAtBoundary {
                position: part_start_pos,
                part_boundary: "start".to_string(),
            },
        )
        .into());
    }
    if part.ends_with('-') {
        return Err(ScopeValidationError::new(
            part,
            ValidationErrorKind::HyphenAtBoundary {
                position: part_start_pos + part.chars().count() - 1,
                part_boundary: "end".to_string(),
            },
        )
        .into());
    }
    if part.starts_with('_') {
        return Err(ScopeValidationError::new(
            part,
            ValidationErrorKind::UnderscoreAtBoundary {
                position: part_start_pos,
                part_boundary: "start".to_string(),
            },
        )
        .into());
    }
    if part.ends_with('_') {
        return Err(ScopeValidationError::new(
            part,
            ValidationErrorKind::UnderscoreAtBoundary {
                position: part_start_pos + part.chars().count() - 1,
                part_boundary: "end".to_string(),
            },
        )
        .into());
    }
    Ok(())
}

/// Parse a scope path string into components.
pub fn parse_scope_path(scope: &str) -> Vec<String> {
    scope
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Format a scope path as a string.
pub fn format_scope_path(parts: &[String]) -> String {
    parts.join(".")
}

/// Validate a scope name according to v0.4.0 rules.
pub fn validate_scope_name(scope: &str) -> Result<()> {
    let original_input = scope;
    let scope = scope.trim();

    // Check empty scope
    if scope.is_empty() {
        return Err(
            ScopeValidationError::new(original_input, ValidationErrorKind::EmptyScope).into(),
        );
    }

    // Check maximum length
    const MAX_LENGTH: usize = 256;
    if scope.len() > MAX_LENGTH {
        return Err(ScopeValidationError::new(
            scope,
            ValidationErrorKind::TooLong {
                length: scope.len(),
                maximum: MAX_LENGTH,
            },
        )
        .into());
    }

    // Check leading dot
    if scope.starts_with('.') {
        return Err(ScopeValidationError::new(scope, ValidationErrorKind::LeadingDot).into());
    }

    // Check trailing dot
    if scope.ends_with('.') {
        return Err(ScopeValidationError::new(scope, ValidationErrorKind::TrailingDot).into());
    }

    // Character-by-character validation with position tracking
    for (byte_idx, ch) in scope.char_indices() {
        let position = char_position_from_byte_index(scope, byte_idx);

        if !ch.is_ascii() {
            return Err(ScopeValidationError::new(
                scope,
                ValidationErrorKind::NonAsciiCharacter {
                    character: ch,
                    position,
                },
            )
            .into());
        }
        if is_unicode_whitespace(ch) {
            return Err(ScopeValidationError::new(
                scope,
                ValidationErrorKind::UnicodeWhitespace {
                    character: ch,
                    position,
                },
            )
            .into());
        }
        if ch == ' ' {
            return Err(ScopeValidationError::new(
                scope,
                ValidationErrorKind::ContainsSpace { position },
            )
            .into());
        }
        if !is_valid_scope_char(ch) {
            return Err(ScopeValidationError::new(
                scope,
                ValidationErrorKind::InvalidCharacter {
                    character: ch,
                    position,
                },
            )
            .into());
        }
    }

    // Check consecutive dots
    if scope.contains("..") {
        if let Some(idx) = scope.find("..") {
            let start = char_position_from_byte_index(scope, idx);
            let end = start + 1;
            return Err(ScopeValidationError::new(
                scope,
                ValidationErrorKind::ConsecutiveDots { start, end },
            )
            .into());
        }
    }

    // Validate part boundaries
    let parts: Vec<&str> = scope.split('.').collect();
    let mut current_pos = 1;
    for part in parts {
        validate_part_boundaries(part, current_pos)?;
        current_pos += part.chars().count() + 1;
    }

    Ok(())
}

/// Find a vault file in the current directory or parents.
pub fn find_vault_file() -> Option<PathBuf> {
    let current_dir = std::env::current_dir().ok()?;

    // Check current directory
    for name in &[
        "vault.toml",
        ".vault.toml",
        "credentials.toml",
        "vault.md",
        ".vault.md",
    ] {
        let path = current_dir.join(name);
        if path.exists() {
            return Some(path);
        }
    }

    // Check parent directories
    let mut dir = current_dir.parent();
    while let Some(parent) = dir {
        for name in &[
            "vault.toml",
            ".vault.toml",
            "credentials.toml",
            "vault.md",
            ".vault.md",
        ] {
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
        let parts: Vec<&str> = scope.split('.').collect();
        let level = parts.len() - 1;
        let is_last = i == scopes.len() - 1 || {
            // Check if this is the last item at its level
            if i + 1 < scopes.len() {
                let next_parts: Vec<&str> = scopes[i + 1].split('.').collect();
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

/// Prompt user with a yes/no question, with default value
pub fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    use std::io::{self, Write};

    let default_hint = if default { "Y/n" } else { "y/N" };
    print!("{prompt} [{default_hint}]: ");
    io::stdout().flush().map_err(VaultError::Io)?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(VaultError::Io)?;

    let input = input.trim().to_lowercase();
    if input.is_empty() {
        Ok(default)
    } else {
        Ok(input == "y" || input == "yes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scope_path() {
        assert_eq!(
            parse_scope_path("personal.banking.chase"),
            vec!["personal", "banking", "chase"]
        );
        assert_eq!(parse_scope_path(".personal."), vec!["personal"]);
        assert_eq!(parse_scope_path(""), Vec::<String>::new());
    }

    #[test]
    fn test_validate_scope_name() {
        assert!(validate_scope_name("personal.banking").is_ok());
        assert!(validate_scope_name("work-stuff").is_ok());
        assert!(validate_scope_name("test_123").is_ok());

        assert!(validate_scope_name("").is_err());
        assert!(validate_scope_name("with<angle>").is_err());
        assert!(validate_scope_name("with|pipe").is_err());
        assert!(validate_scope_name("personal..").is_err());
        assert!(validate_scope_name("personal...").is_err());
        assert!(validate_scope_name(".personal").is_err());
        assert!(validate_scope_name("personal.").is_err());
    }

    #[test]
    fn test_format_tree() {
        let scopes = vec![
            "personal".to_string(),
            "personal.banking".to_string(),
            "personal.banking.chase".to_string(),
            "personal.email".to_string(),
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
