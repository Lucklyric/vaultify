// Unit tests for scope validation logic (User Story 1)
// These tests verify the enhanced validation with position-aware error messages

use vaultify::utils::validate_scope_name;

// ============================================================================
// Basic Validation Tests (T027-T033)
// ============================================================================

#[test]
fn test_space_rejection_at_start() {
    // T027: Test space rejection at start (without leading trim - space after first char)
    let result = validate_scope_name("w ork");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("position 2"));
    assert!(err_msg.contains("space") || err_msg.contains("whitespace"));
}

#[test]
fn test_space_rejection_in_middle() {
    // T028: Test space rejection in middle
    let result = validate_scope_name("work email");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("position 5"));
    assert!(err_msg.contains("space") || err_msg.contains("whitespace"));
}

#[test]
fn test_space_rejection_at_end() {
    // T029: Test space rejection at end (without trailing trim - space before last char)
    let result = validate_scope_name("wor k");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("space") || err_msg.contains("whitespace"));
}

#[test]
fn test_consecutive_dots_rejection() {
    // T030: Test consecutive dots rejection
    let result = validate_scope_name("work..email");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("consecutive dots") || err_msg.contains("empty part"));
}

#[test]
fn test_leading_dot_rejection() {
    // T031: Test leading dot rejection
    let result = validate_scope_name(".work");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("position 1"));
    assert!(err_msg.contains("leading") || err_msg.contains("start"));
}

#[test]
fn test_trailing_dot_rejection() {
    // T032: Test trailing dot rejection
    let result = validate_scope_name("work.");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("trailing") || err_msg.contains("end"));
}

#[test]
fn test_empty_string_rejection() {
    // T033: Test empty string rejection
    let result = validate_scope_name("");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("empty"));
}

// ============================================================================
// Character Set Tests (T034-T038)
// ============================================================================

#[test]
fn test_ascii_alphanumeric_acceptance() {
    // T034: Test ASCII alphanumeric acceptance [A-Za-z0-9]
    assert!(validate_scope_name("Work123").is_ok());
    assert!(validate_scope_name("abc").is_ok());
    assert!(validate_scope_name("XYZ").is_ok());
    assert!(validate_scope_name("test456").is_ok());
}

#[test]
fn test_non_ascii_letter_rejection() {
    // T035: Test non-ASCII letter rejection (café, 日本)
    let result = validate_scope_name("café");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("non-ASCII") || err_msg.contains("ASCII"));

    let result = validate_scope_name("日本");
    assert!(result.is_err());
}

#[test]
fn test_special_character_rejection() {
    // T036: Test special character rejection (<, >, |, \)
    let result = validate_scope_name("work<email>");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("position 5"));
    assert!(err_msg.contains("invalid") || err_msg.contains("character"));

    assert!(validate_scope_name("work>email").is_err());
    assert!(validate_scope_name("work|email").is_err());
    assert!(validate_scope_name("work\\email").is_err());
}

#[test]
fn test_unicode_whitespace_rejection() {
    // T037: Test Unicode whitespace rejection (NBSP, EM SPACE, THIN SPACE)
    // NBSP (U+00A0)
    let nbsp = "work\u{00A0}email";
    let result = validate_scope_name(nbsp);
    assert!(result.is_err());

    // EM SPACE (U+2003)
    let em_space = "work\u{2003}email";
    assert!(validate_scope_name(em_space).is_err());

    // THIN SPACE (U+2009)
    let thin_space = "work\u{2009}email";
    assert!(validate_scope_name(thin_space).is_err());
}

#[test]
fn test_tab_and_newline_rejection() {
    // T038: Test tab and newline rejection
    let result = validate_scope_name("work\temail");
    assert!(result.is_err());

    let result = validate_scope_name("work\nemail");
    assert!(result.is_err());
}

// ============================================================================
// Part Boundary Rules Tests (T039-T044)
// ============================================================================

#[test]
fn test_hyphen_at_part_start_rejection() {
    // T039: Test hyphen at part start rejection (-work, a.-b)
    let result = validate_scope_name("-work");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("hyphen") || err_msg.contains("start"));

    let result = validate_scope_name("a.-b");
    assert!(result.is_err());
}

#[test]
fn test_hyphen_at_part_end_rejection() {
    // T040: Test hyphen at part end rejection (work-, a.b-)
    let result = validate_scope_name("work-");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("hyphen") || err_msg.contains("end"));

    let result = validate_scope_name("a.b-");
    assert!(result.is_err());
}

#[test]
fn test_hyphen_in_part_middle_acceptance() {
    // T041: Test hyphen in part middle acceptance (my-work)
    assert!(validate_scope_name("my-work").is_ok());
    assert!(validate_scope_name("a.my-work").is_ok());
    assert!(validate_scope_name("my-work.email").is_ok());
    assert!(validate_scope_name("my-work.my-email").is_ok());
}

#[test]
fn test_underscore_at_part_start_rejection() {
    // T042: Test underscore at part start rejection (_work, a._b)
    let result = validate_scope_name("_work");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("underscore") || err_msg.contains("start"));

    let result = validate_scope_name("a._b");
    assert!(result.is_err());
}

#[test]
fn test_underscore_at_part_end_rejection() {
    // T043: Test underscore at part end rejection (work_, a.b_)
    let result = validate_scope_name("work_");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("underscore") || err_msg.contains("end"));

    let result = validate_scope_name("a.b_");
    assert!(result.is_err());
}

#[test]
fn test_underscore_in_part_middle_acceptance() {
    // T044: Test underscore in part middle acceptance (my_work)
    assert!(validate_scope_name("my_work").is_ok());
    assert!(validate_scope_name("a.my_work").is_ok());
    assert!(validate_scope_name("my_work.email").is_ok());
    assert!(validate_scope_name("my_work.my_email").is_ok());
}

// ============================================================================
// Whitespace Handling Tests (T045-T048)
// ============================================================================

#[test]
fn test_leading_whitespace_trimming() {
    // T045: Test leading whitespace trimming (" work" → "work")
    // After trimming, "work" should be valid
    assert!(validate_scope_name(" work").is_ok());
    assert!(validate_scope_name("  work").is_ok());
    assert!(validate_scope_name("\twork").is_ok());
}

#[test]
fn test_trailing_whitespace_trimming() {
    // T046: Test trailing whitespace trimming ("work " → "work")
    assert!(validate_scope_name("work ").is_ok());
    assert!(validate_scope_name("work  ").is_ok());
    assert!(validate_scope_name("work\t").is_ok());
}

#[test]
fn test_both_leading_and_trailing_trimming() {
    // T047: Test both leading and trailing trimming
    assert!(validate_scope_name(" work ").is_ok());
    assert!(validate_scope_name("  work  ").is_ok());
    assert!(validate_scope_name("\twork\t").is_ok());
}

#[test]
fn test_whitespace_in_middle_still_rejected_after_trim() {
    // T048: Test whitespace in middle still rejected after trim
    let result = validate_scope_name(" work email ");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("space") || err_msg.contains("whitespace"));
}

// ============================================================================
// Multi-level Scopes Tests (T049-T052)
// ============================================================================

#[test]
fn test_single_part_acceptance() {
    // T049: Test single part acceptance ("work")
    assert!(validate_scope_name("work").is_ok());
    assert!(validate_scope_name("personal").is_ok());
    assert!(validate_scope_name("test123").is_ok());
}

#[test]
fn test_two_levels_acceptance() {
    // T050: Test two levels acceptance ("work.email")
    assert!(validate_scope_name("work.email").is_ok());
    assert!(validate_scope_name("personal.banking").is_ok());
}

#[test]
fn test_deep_nesting_acceptance() {
    // T051: Test deep nesting acceptance ("a.b.c.d.e.f.g.h")
    assert!(validate_scope_name("a.b.c.d.e.f.g.h").is_ok());
    assert!(validate_scope_name("company.division.team.project.env.service").is_ok());
}

#[test]
fn test_mixed_valid_characters() {
    // T052: Test mixed valid characters ("my2-work_email.test3")
    assert!(validate_scope_name("my2-work_email.test3").is_ok());
    assert!(validate_scope_name("project-2025.api_v2.token").is_ok());
    assert!(validate_scope_name("server1.db-connection.password_123").is_ok());
}

// ============================================================================
// Position Accuracy Tests (T053-T057)
// ============================================================================

#[test]
fn test_position_reporting_for_spaces() {
    // T053: Test position reporting for spaces ("work email" → position 5)
    let result = validate_scope_name("work email");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("position 5"),
        "Error message should contain 'position 5', got: {err_msg}"
    );
}

#[test]
fn test_position_range_for_consecutive_dots() {
    // T054: Test position range for consecutive dots ("work..email" → position 5-6)
    let result = validate_scope_name("work..email");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // Should mention position 5 or 6 or a range
    assert!(err_msg.contains("position") && (err_msg.contains("5") || err_msg.contains("6")));
}

#[test]
fn test_position_for_leading_dot() {
    // T055: Test position for leading dot (".work" → position 1)
    let result = validate_scope_name(".work");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("position 1"));
}

#[test]
fn test_position_for_trailing_dot() {
    // T056: Test position for trailing dot ("work." → position 5)
    let result = validate_scope_name("work.");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // Position should be at or near the trailing dot
    assert!(err_msg.contains("position"));
}

#[test]
fn test_position_for_special_char() {
    // T057: Test position for special char ("work<email>" → position 5)
    let result = validate_scope_name("work<email>");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("position 5"));
}

// ============================================================================
// Error Message Format Tests (T058-T063)
// ============================================================================

#[test]
fn test_multi_section_format_has_6_lines() {
    // T058: Verify multi-section format has 6 lines
    let result = validate_scope_name("work email");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    let lines: Vec<&str> = err_msg.lines().collect();
    assert_eq!(
        lines.len(),
        6,
        "Error message should have exactly 6 lines, got {}: {}",
        lines.len(),
        err_msg
    );
}

#[test]
fn test_position_appears_in_line_1() {
    // T059: Verify position appears in line 1
    let result = validate_scope_name("work email");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    let lines: Vec<&str> = err_msg.lines().collect();
    assert!(
        lines[0].contains("position"),
        "Line 1 should contain 'position': {}",
        lines[0]
    );
}

#[test]
fn test_issue_label_in_line_3() {
    // T060: Verify "Issue:" label in line 3
    let result = validate_scope_name("work email");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    let lines: Vec<&str> = err_msg.lines().collect();
    assert!(
        lines[2].starts_with("Issue:"),
        "Line 3 should start with 'Issue:': {}",
        lines[2]
    );
}

#[test]
fn test_expected_format_in_line_4() {
    // T061: Verify "Expected format:" in line 4
    let result = validate_scope_name("work email");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    let lines: Vec<&str> = err_msg.lines().collect();
    assert!(
        lines[3].starts_with("Expected format:"),
        "Line 4 should start with 'Expected format:': {}",
        lines[3]
    );
}

#[test]
fn test_example_in_line_6() {
    // T062: Verify "Example:" in line 6
    let result = validate_scope_name("work email");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    let lines: Vec<&str> = err_msg.lines().collect();
    assert!(
        lines[5].starts_with("Example:"),
        "Line 6 should start with 'Example:': {}",
        lines[5]
    );
}

#[test]
fn test_blank_lines_at_positions_2_and_5() {
    // T063: Verify blank lines at positions 2 and 5
    let result = validate_scope_name("work email");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    let lines: Vec<&str> = err_msg.lines().collect();
    assert_eq!(lines[1], "", "Line 2 should be blank: '{}'", lines[1]);
    assert_eq!(lines[4], "", "Line 5 should be blank: '{}'", lines[4]);
}

// ============================================================================
// Edge Cases Tests (T064-T068)
// ============================================================================

#[test]
fn test_maximum_scope_length() {
    // T064: Test maximum scope length (256 chars)
    let max_scope = "a".repeat(256);
    assert!(validate_scope_name(&max_scope).is_ok());
}

#[test]
fn test_scope_exceeding_maximum_length() {
    // T065: Test scope exceeding maximum length
    let too_long = "a".repeat(257);
    let result = validate_scope_name(&too_long);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("too long") || err_msg.contains("maximum") || err_msg.contains("256"));
}

#[test]
fn test_single_dot_only() {
    // T066: Test single dot only (".")
    let result = validate_scope_name(".");
    assert!(result.is_err());
}

#[test]
fn test_case_sensitivity_preserved() {
    // T067: Test case sensitivity preserved ("Work.Email")
    assert!(validate_scope_name("Work.Email").is_ok());
    assert!(validate_scope_name("WORK.EMAIL").is_ok());
    assert!(validate_scope_name("work.email").is_ok());
    // All three should be considered different scopes (case is preserved)
}

#[test]
fn test_digits_at_start() {
    // T068: Test digits at start ("2work.3email")
    assert!(validate_scope_name("2work.3email").is_ok());
    assert!(validate_scope_name("123").is_ok());
    assert!(validate_scope_name("2025.project.api").is_ok());
}
