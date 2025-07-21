use std::collections::HashMap;
use vaultify::{
    models::{VaultDocument, VaultEntry},
    toml_parser::TomlParser,
};

#[test]
fn test_smart_group_insertion() {
    // Create a document with initial entries
    let mut doc = VaultDocument::new();

    // Add a.a2
    doc.add_entry(VaultEntry {
        scope_path: vec!["a".to_string(), "a2".to_string()],
        description: "a.a2 credentials".to_string(),
        encrypted_content: "encrypted_a_a2".to_string(),
        salt: Some(vec![1, 2, 3]),
        custom_fields: HashMap::new(),
    })
    .unwrap();

    // Add b.a2
    doc.add_entry(VaultEntry {
        scope_path: vec!["b".to_string(), "a2".to_string()],
        description: "b.a2 credentials".to_string(),
        encrypted_content: "encrypted_b_a2".to_string(),
        salt: Some(vec![4, 5, 6]),
        custom_fields: HashMap::new(),
    })
    .unwrap();

    // Add a.a11 - should be inserted after a.a2, not at the end
    doc.add_entry(VaultEntry {
        scope_path: vec!["a".to_string(), "a11".to_string()],
        description: "a.a11 credentials".to_string(),
        encrypted_content: "encrypted_a_a11".to_string(),
        salt: Some(vec![7, 8, 9]),
        custom_fields: HashMap::new(),
    })
    .unwrap();

    // Verify the order
    assert_eq!(doc.entries.len(), 3);
    assert_eq!(doc.entries[0].scope_path, vec!["a", "a2"]);
    assert_eq!(doc.entries[1].scope_path, vec!["a", "a11"]); // Should be here, not at end
    assert_eq!(doc.entries[2].scope_path, vec!["b", "a2"]);

    // Test TOML formatting preserves the order
    let parser = TomlParser::new();
    let toml_output = parser.format(&doc);

    // Find positions of each entry in the output
    let a_a2_pos = toml_output.find("[a.a2]").expect("Should find [a.a2]");
    let a_a11_pos = toml_output.find("[a.a11]").expect("Should find [a.a11]");
    let b_a2_pos = toml_output.find("[b.a2]").expect("Should find [b.a2]");

    // Verify order in TOML output
    assert!(a_a2_pos < a_a11_pos, "a.a2 should come before a.a11");
    assert!(a_a11_pos < b_a2_pos, "a.a11 should come before b.a2");
}

#[test]
fn test_multiple_level_group_insertion() {
    let mut doc = VaultDocument::new();

    // Add entries in mixed order
    doc.add_entry(VaultEntry {
        scope_path: vec!["work".to_string(), "email".to_string(), "gmail".to_string()],
        description: "Work Gmail".to_string(),
        encrypted_content: "enc1".to_string(),
        salt: Some(vec![1]),
        custom_fields: HashMap::new(),
    })
    .unwrap();

    doc.add_entry(VaultEntry {
        scope_path: vec!["personal".to_string(), "banking".to_string()],
        description: "Personal banking".to_string(),
        encrypted_content: "enc2".to_string(),
        salt: Some(vec![2]),
        custom_fields: HashMap::new(),
    })
    .unwrap();

    // Add another work entry - should go after existing work entries
    doc.add_entry(VaultEntry {
        scope_path: vec!["work".to_string(), "vpn".to_string()],
        description: "Work VPN".to_string(),
        encrypted_content: "enc3".to_string(),
        salt: Some(vec![3]),
        custom_fields: HashMap::new(),
    })
    .unwrap();

    // Verify order
    assert_eq!(doc.entries[0].scope_path, vec!["work", "email", "gmail"]);
    assert_eq!(doc.entries[1].scope_path, vec!["work", "vpn"]); // Grouped with work
    assert_eq!(doc.entries[2].scope_path, vec!["personal", "banking"]);
}
