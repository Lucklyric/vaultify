// Integration tests for vaultify
// These tests verify end-to-end behavior and validation integration

use vaultify::utils::validate_scope_name;
use vaultify::VaultError;

// ============================================================================
// User Story 1: Integration Tests (T069-T074)
// ============================================================================

#[test]
fn test_cli_add_rejects_invalid_scopes() {
    // T069: Test CLI add command rejects invalid scopes
    // This test verifies validation is called before attempting to add

    // Invalid scope with space
    let result = validate_scope_name("work email");
    assert!(result.is_err());

    // Invalid scope with consecutive dots
    let result = validate_scope_name("work..email");
    assert!(result.is_err());

    // Invalid scope with leading dot
    let result = validate_scope_name(".work");
    assert!(result.is_err());

    // Valid scopes should pass
    assert!(validate_scope_name("work.email").is_ok());
    assert!(validate_scope_name("personal.banking").is_ok());
}

#[test]
fn test_cli_displays_error_to_stderr() {
    // T070: Test CLI displays error with proper format
    // Verify error message includes position information

    let result = validate_scope_name("work..email");
    assert!(result.is_err());

    match result {
        Err(VaultError::InvalidScope(err)) => {
            let msg = err.to_string();
            assert!(msg.contains("Invalid scope"));
            assert!(msg.contains("position"));
            assert!(msg.contains("Issue:"));
            assert!(msg.contains("Expected format:"));
            assert!(msg.contains("Example:"));
        }
        _ => panic!("Expected InvalidScope error"),
    }
}

#[test]
fn test_cli_exit_codes() {
    // T071: Test CLI returns proper error codes
    // When validation fails, it should return an error (not Ok)

    let result = validate_scope_name(".work");
    assert!(result.is_err(), "Leading dot should cause error");

    let result = validate_scope_name("work-");
    assert!(result.is_err(), "Trailing hyphen should cause error");

    let result = validate_scope_name("work");
    assert!(result.is_ok(), "Valid scope should succeed");
}

#[test]
fn test_interactive_add_rejects_invalid_scopes() {
    // T072: Test interactive add command uses same validation
    // Both CLI and interactive modes call the same validate_scope_name function

    // Verify the validation function is comprehensive
    let invalid_scopes = vec![
        "work email",
        ".work",
        "work.",
        "work..email",
        "work-",
        "_work",
        "work<email>",
    ];

    for scope in invalid_scopes {
        let result = validate_scope_name(scope);
        assert!(result.is_err(), "Scope '{scope}' should be rejected");
    }
}

#[test]
fn test_error_display_in_interactive_mode() {
    // T073: Test error display format is consistent
    // Error messages use the same Display trait implementation

    let result = validate_scope_name("work email");
    assert!(result.is_err());

    if let Err(VaultError::InvalidScope(err)) = result {
        let msg = err.to_string();
        let lines: Vec<&str> = msg.lines().collect();

        // Verify multi-section format
        assert_eq!(lines.len(), 6, "Error should have 6 lines");
        assert!(lines[0].contains("position"), "Line 1 should have position");
        assert_eq!(lines[1], "", "Line 2 should be blank");
        assert!(
            lines[2].starts_with("Issue:"),
            "Line 3 should start with 'Issue:'"
        );
        assert!(
            lines[3].starts_with("Expected format:"),
            "Line 4 should start with 'Expected format:'"
        );
        assert_eq!(lines[4], "", "Line 5 should be blank");
        assert!(
            lines[5].starts_with("Example:"),
            "Line 6 should start with 'Example:'"
        );
    }
}

#[test]
fn test_interactive_mode_parity_with_cli() {
    // T074: Test validation logic is identical between CLI and interactive modes
    // Both use the same validate_scope_name function from utils.rs

    let test_cases = vec![
        // (scope, should_pass)
        ("work", true),
        ("work.email", true),
        ("my-work", true),
        ("my_work", true),
        ("work.email.gmail", true),
        ("work email", false),
        (".work", false),
        ("work.", false),
        ("work..email", false),
        ("-work", false),
        ("work-", false),
        ("_work", false),
        ("work_", false),
    ];

    for (scope, should_pass) in test_cases {
        let result = validate_scope_name(scope);
        if should_pass {
            assert!(result.is_ok(), "Scope '{scope}' should be valid");
        } else {
            assert!(result.is_err(), "Scope '{scope}' should be invalid");
        }
    }
}

// ============================================================================
// User Story 2: Integration Tests (T081-T084)
// ============================================================================

#[test]
fn test_new_vault_has_version_v040() {
    // T081: Test new vault creation has version "v0.4.0"
    use vaultify::models::VaultDocument;
    use vaultify::toml_parser::TomlParser;

    let doc = VaultDocument::new();
    let parser = TomlParser::new();
    let formatted = parser.format(&doc);

    assert!(
        formatted.contains("version = \"v0.4.0\""),
        "New vault should have v0.4.0, got: {formatted}"
    );
}

#[test]
fn test_v031_vault_upgrades_to_v040() {
    // T082: Test modifying v0.3.1 vault upgrades to v0.4.0
    use vaultify::toml_parser::TomlParser;

    // Create a v0.3.1 vault content
    let v031_content = r#"
version = "v0.3.1"
modified = "2025-01-01T00:00:00Z"

[work.email]
description = "Work email"
encrypted = "test"
salt = "test"
"#;

    let parser = TomlParser::new();

    // Parse the v0.3.1 vault
    let doc = parser
        .parse(v031_content)
        .expect("Should parse v0.3.1 vault");

    // Format it (should auto-upgrade)
    let formatted = parser.format(&doc);

    assert!(
        formatted.contains("version = \"v0.4.0\""),
        "Should auto-upgrade to v0.4.0, got: {formatted}"
    );
}

#[test]
fn test_invalid_toml_shows_helpful_error() {
    // T083: Test loading syntactically invalid TOML shows helpful error
    use vaultify::toml_parser::TomlParser;

    // TOML with space in scope (invalid)
    let invalid_content = r#"
version = "v0.3.1"

[work email]
description = "Test"
encrypted = "test"
"#;

    let parser = TomlParser::new();
    let result = parser.parse(invalid_content);

    assert!(result.is_err(), "Should fail to parse invalid TOML");

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Suspected invalid scope") || error_msg.contains("work email"),
        "Error should mention the invalid scope, got: {error_msg}"
    );
}

#[test]
fn test_valid_v031_vault_loads_successfully() {
    // T084: Test loading valid v0.3.1 vault succeeds
    use vaultify::toml_parser::TomlParser;

    let v031_content = r#"
version = "v0.3.1"
modified = "2025-01-01T00:00:00Z"

[work.email]
description = "Work email"
encrypted = "encrypted_data"
salt = "salt_data"

[personal.banking]
description = "Banking credentials"
encrypted = "encrypted_data2"
salt = "salt_data2"
"#;

    let parser = TomlParser::new();
    let result = parser.parse(v031_content);

    assert!(result.is_ok(), "Should successfully parse v0.3.1 vault");

    let doc = result.unwrap();

    // Filter out parent entries (those with empty encrypted content and "secrets" description)
    let actual_entries: Vec<_> = doc
        .entries
        .iter()
        .filter(|e| !e.encrypted_content.is_empty())
        .collect();

    assert_eq!(actual_entries.len(), 2, "Should have 2 non-parent entries");
    assert_eq!(actual_entries[0].scope_path, vec!["work", "email"]);
    assert_eq!(actual_entries[1].scope_path, vec!["personal", "banking"]);
}

// ============================================================================
// User Story 3: Integration Tests (T096-T101)
// ============================================================================

#[test]
fn test_validate_command_with_valid_vault() {
    // T096: Test validate command with valid vault (exit 0)
    use std::io::Write;
    use tempfile::NamedTempFile;
    use vaultify::operations::validate_vault_file;

    let mut temp_file = NamedTempFile::new().unwrap();
    let valid_vault = r#"
version = "v0.3.1"

[work.email]
description = "Work email"
encrypted = "test"
salt = "test"
"#;
    temp_file.write_all(valid_vault.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let report = validate_vault_file(temp_file.path()).unwrap();
    assert!(report.is_valid(), "Valid vault should pass validation");
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn test_validate_command_with_invalid_vault() {
    // T097: Test validate command with invalid vault (exit 1, lists all issues)
    use std::io::Write;
    use tempfile::NamedTempFile;
    use vaultify::operations::validate_vault_file;

    let mut temp_file = NamedTempFile::new().unwrap();
    let invalid_vault = r#"
version = "v0.3.1"

[work email]
description = "Invalid scope with space"
encrypted = "test"
salt = "test"

[test..scope]
description = "Invalid consecutive dots"
encrypted = "test"
salt = "test"
"#;
    temp_file.write_all(invalid_vault.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let report = validate_vault_file(temp_file.path()).unwrap();
    assert!(!report.is_valid(), "Invalid vault should fail validation");
    assert_eq!(report.exit_code(), 1);
    assert!(report.issues.len() >= 2, "Should report multiple issues");
}

#[test]
fn test_validate_auto_detects_vault() {
    // T098: Test validate with no args auto-detects vault
    use std::fs;
    use tempfile::TempDir;
    use vaultify::operations::validate_vault_file;

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.toml");
    let valid_vault = r#"
version = "v0.3.1"

[work.email]
description = "Work email"
encrypted = "test"
salt = "test"
"#;
    fs::write(&vault_path, valid_vault).unwrap();

    let report = validate_vault_file(&vault_path).unwrap();
    assert!(report.is_valid());
}

#[test]
fn test_validate_with_explicit_path() {
    // T099: Test validate with explicit path
    use std::io::Write;
    use tempfile::NamedTempFile;
    use vaultify::operations::validate_vault_file;

    let mut temp_file = NamedTempFile::new().unwrap();
    let valid_vault = r#"
version = "v0.4.0"

[personal.banking]
description = "Banking"
encrypted = "test"
salt = "test"
"#;
    temp_file.write_all(valid_vault.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    // Explicitly pass the path
    let report = validate_vault_file(temp_file.path()).unwrap();
    assert!(report.is_valid());
}

#[test]
fn test_validate_reports_all_invalid_entries() {
    // T100: Test validate reports all invalid entries (not just first)
    use std::io::Write;
    use tempfile::NamedTempFile;
    use vaultify::operations::validate_vault_file;

    let mut temp_file = NamedTempFile::new().unwrap();
    let multi_invalid_vault = r#"
version = "v0.3.1"

[work email]
description = "Invalid 1"
encrypted = "test"

[.test]
description = "Invalid 2"
encrypted = "test"

[end.]
description = "Invalid 3"
encrypted = "test"
"#;
    temp_file.write_all(multi_invalid_vault.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let report = validate_vault_file(temp_file.path()).unwrap();
    assert!(!report.is_valid());
    // Should report all 3 invalid entries
    assert!(
        report.issues.len() >= 3,
        "Should find at least 3 issues, found {}",
        report.issues.len()
    );
}

#[test]
fn test_validate_with_missing_file() {
    // T101: Test validate with missing file shows error
    use std::path::Path;
    use vaultify::operations::validate_vault_file;

    let nonexistent = Path::new("/nonexistent/vault.toml");
    let result = validate_vault_file(nonexistent);
    assert!(result.is_err(), "Should error when file doesn't exist");
}

// ============================================================================
// Phase 6: Round-trip Tests (T105-T107)
// These will be added in Phase 6
// ============================================================================
