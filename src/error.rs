//! Error types for vaultify.

use std::path::PathBuf;
use thiserror::Error;

/// Specific types of scope validation errors with position data
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationErrorKind {
    /// Scope contains a space character
    ContainsSpace {
        position: usize, // 1-based character position
    },

    /// Scope contains consecutive dots
    ConsecutiveDots {
        start: usize, // First dot position (1-based)
        end: usize,   // Last dot position (1-based)
    },

    /// Scope starts with a dot
    LeadingDot,

    /// Scope ends with a dot
    TrailingDot,

    /// Scope contains an invalid character (not in [A-Za-z0-9._-])
    InvalidCharacter {
        character: char,
        position: usize, // 1-based
    },

    /// Hyphen at part boundary (start or end of part)
    HyphenAtBoundary {
        position: usize,       // 1-based
        part_boundary: String, // "start" or "end"
    },

    /// Underscore at part boundary (start or end of part)
    UnderscoreAtBoundary {
        position: usize,       // 1-based
        part_boundary: String, // "start" or "end"
    },

    /// Scope is empty after trimming
    EmptyScope,

    /// Scope contains non-ASCII character
    NonAsciiCharacter {
        character: char,
        position: usize, // 1-based
    },

    /// Scope contains Unicode whitespace variant (NBSP, EM SPACE, etc.)
    UnicodeWhitespace {
        character: char,
        position: usize, // 1-based
    },

    /// Scope exceeds maximum length
    TooLong {
        length: usize,
        maximum: usize, // 256
    },
}

/// Complete validation error with input context and suggestion
#[derive(Debug, Clone)]
pub struct ScopeValidationError {
    /// The invalid input that was validated
    pub input: String,

    /// The specific type of validation failure
    pub kind: ValidationErrorKind,

    /// A corrected version of the input (for error messages)
    pub suggestion: String,
}

impl ScopeValidationError {
    /// Create a new validation error with automatic suggestion generation
    pub fn new(input: impl Into<String>, kind: ValidationErrorKind) -> Self {
        let input = input.into();
        let suggestion = generate_suggestion(&input, &kind);
        Self {
            input,
            kind,
            suggestion,
        }
    }

    /// Get the position where the error occurred
    pub fn position(&self) -> String {
        use ValidationErrorKind::*;
        match &self.kind {
            ContainsSpace { position } => position.to_string(),
            InvalidCharacter { position, .. } => position.to_string(),
            NonAsciiCharacter { position, .. } => position.to_string(),
            UnicodeWhitespace { position, .. } => position.to_string(),
            HyphenAtBoundary { position, .. } => position.to_string(),
            UnderscoreAtBoundary { position, .. } => position.to_string(),
            ConsecutiveDots { start, end } => format!("{start}-{end}"),
            LeadingDot => "1".to_string(),
            TrailingDot => {
                let len = self.input.chars().count();
                len.to_string()
            }
            EmptyScope => "N/A".to_string(),
            TooLong { .. } => "N/A".to_string(),
        }
    }

    /// Get a brief description of the issue
    pub fn issue(&self) -> &str {
        use ValidationErrorKind::*;
        match &self.kind {
            ContainsSpace { .. } => "found space character",
            ConsecutiveDots { .. } => "found consecutive dots",
            LeadingDot => "starts with dot",
            TrailingDot => "ends with dot",
            InvalidCharacter { .. } => "found invalid character",
            HyphenAtBoundary { part_boundary, .. } => {
                if part_boundary == "start" {
                    "hyphen cannot appear at start of part"
                } else {
                    "hyphen cannot appear at end of part"
                }
            }
            UnderscoreAtBoundary { part_boundary, .. } => {
                if part_boundary == "start" {
                    "underscore cannot appear at start of part"
                } else {
                    "underscore cannot appear at end of part"
                }
            }
            EmptyScope => "scope is empty",
            NonAsciiCharacter { .. } => "found non-ASCII character",
            UnicodeWhitespace { .. } => "found Unicode whitespace",
            TooLong { .. } => "scope exceeds maximum length",
        }
    }

    /// Get detailed explanation of the issue
    pub fn explanation(&self) -> String {
        use ValidationErrorKind::*;
        match &self.kind {
            ContainsSpace { .. } =>
                "Spaces are not supported in scope names".to_string(),
            ConsecutiveDots { .. } =>
                "Cannot have empty parts between dots".to_string(),
            LeadingDot =>
                "Scope cannot begin with a separator".to_string(),
            TrailingDot =>
                "Scope cannot end with a separator".to_string(),
            InvalidCharacter { character, .. } =>
                format!("Character '{character}' is not allowed. Only alphanumeric, hyphens, underscores, and dots are permitted"),
            HyphenAtBoundary { part_boundary, .. } =>
                format!("Hyphens must be within a part name, not at the {part_boundary}"),
            UnderscoreAtBoundary { part_boundary, .. } =>
                format!("Underscores must be within a part name, not at the {part_boundary}"),
            EmptyScope =>
                "Scope name cannot be empty".to_string(),
            NonAsciiCharacter { character, .. } =>
                format!("Character '{character}' is non-ASCII. Only ASCII characters [A-Za-z0-9._-] are allowed"),
            UnicodeWhitespace { character, .. } =>
                format!("Unicode whitespace '{}' (U+{:04X}) is not allowed. Use regular spaces which will be rejected", *character, *character as u32),
            TooLong { length, maximum } =>
                format!("Scope length ({length} characters) exceeds maximum allowed ({maximum} characters)"),
        }
    }

    /// Get expected format guidance
    pub fn expected(&self) -> &str {
        use ValidationErrorKind::*;
        match &self.kind {
            ContainsSpace { .. } => "Use dots to separate parts",
            ConsecutiveDots { .. } => "Each dot must separate valid part names",
            LeadingDot => "Must start with alphanumeric character",
            TrailingDot => "Must end with alphanumeric character",
            InvalidCharacter { .. } => "Use simple characters for scope parts",
            HyphenAtBoundary { .. } => {
                "Place hyphens within part names: 'my-work' not '-work' or 'work-'"
            }
            UnderscoreAtBoundary { .. } => {
                "Place underscores within part names: 'my_work' not '_work' or 'work_'"
            }
            EmptyScope => "Provide a non-empty scope name",
            NonAsciiCharacter { .. } | UnicodeWhitespace { .. } => {
                "Only ASCII alphanumeric, dots, hyphens, and underscores"
            }
            TooLong { .. } => "Shorten scope name to 256 characters or less",
        }
    }
}

impl std::fmt::Display for ScopeValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Line 1: Summary with position
        writeln!(
            f,
            "Invalid scope '{}' at position {}: {}",
            self.input,
            self.position(),
            self.issue()
        )?;

        // Line 2: Blank
        writeln!(f)?;

        // Line 3: Detailed issue explanation
        writeln!(f, "Issue: {}", self.explanation())?;

        // Line 4: Expected format guidance
        writeln!(f, "Expected format: {}", self.expected())?;

        // Line 5: Blank
        writeln!(f)?;

        // Line 6: Corrected example
        write!(
            f,
            "Example: '{}' (instead of '{}')",
            self.suggestion, self.input
        )
    }
}

impl std::error::Error for ScopeValidationError {}

/// Generate a corrected suggestion for invalid scope
fn generate_suggestion(input: &str, kind: &ValidationErrorKind) -> String {
    use ValidationErrorKind::*;
    match kind {
        ContainsSpace { .. } => {
            // Replace spaces with dots
            input.split_whitespace().collect::<Vec<_>>().join(".")
        }
        ConsecutiveDots { .. } => {
            // Remove consecutive dots
            let mut result = String::new();
            let mut last_was_dot = false;
            for ch in input.chars() {
                if ch == '.' {
                    if !last_was_dot {
                        result.push(ch);
                        last_was_dot = true;
                    }
                } else {
                    result.push(ch);
                    last_was_dot = false;
                }
            }
            result
        }
        LeadingDot => {
            // Remove leading dot
            input.trim_start_matches('.').to_string()
        }
        TrailingDot => {
            // Remove trailing dot
            input.trim_end_matches('.').to_string()
        }
        HyphenAtBoundary { .. } => {
            // Remove hyphens at part boundaries
            input
                .split('.')
                .map(|part| part.trim_matches('-'))
                .collect::<Vec<_>>()
                .join(".")
        }
        UnderscoreAtBoundary { .. } => {
            // Remove underscores at part boundaries
            input
                .split('.')
                .map(|part| part.trim_matches('_'))
                .collect::<Vec<_>>()
                .join(".")
        }
        InvalidCharacter { character, .. } => {
            // Remove invalid character
            input.chars().filter(|&c| c != *character).collect()
        }
        NonAsciiCharacter { .. } => {
            // Remove all non-ASCII
            input.chars().filter(|c| c.is_ascii()).collect()
        }
        UnicodeWhitespace { .. } => {
            // Remove Unicode whitespace
            const UNICODE_WS: &[char] =
                &['\u{00A0}', '\u{2003}', '\u{2009}', '\u{200A}', '\u{202F}'];
            input.chars().filter(|c| !UNICODE_WS.contains(c)).collect()
        }
        EmptyScope => {
            // Can't suggest for empty scope
            "(provide a scope name)".to_string()
        }
        TooLong { maximum, .. } => {
            // Truncate with ellipsis
            let truncated: String = input.chars().take(*maximum - 3).collect();
            format!("{truncated}...")
        }
    }
}

/// Main error type for vault operations.
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault file not found: {0}")]
    VaultNotFound(PathBuf),

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Entry already exists: {0}")]
    EntryExists(String),

    #[error("{0}")]
    InvalidScope(#[from] ScopeValidationError),

    #[error("No encrypted content in entry: {0}")]
    NoEncryptedContent(String),

    #[error("No salt found for entry: {0}")]
    NoSalt(String),

    #[error("Decryption failed - incorrect password")]
    DecryptionFailed,

    #[error("Passwords do not match")]
    PasswordMismatch,

    #[error("No secret provided")]
    NoSecret,

    #[error("Operation cancelled by user")]
    Cancelled,

    #[error("Session expired")]
    SessionExpired,

    #[error("Clipboard operation failed")]
    ClipboardFailed,

    #[error("Editor launch failed")]
    EditorFailed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error("Permission error: {0}")]
    Permission(String),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;
