use std::collections::HashMap;
use tempfile::TempDir;
use vaultify::models::VaultEntry;
use vaultify::service::VaultService;

#[test]
fn test_toml_format_integration() {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("test.toml");

    // Create initial TOML content
    let initial_content = r#"version = "v0.3"
created = "2025-01-17T10:00:00Z"

[personal.banking]
description = "Banking info"
encrypted = "YmFzZTY0X2VuY3J5cHRlZF9kYXRh"
salt = "YmFzZTY0X3NhbHQ="
last_rotated = "2025-01-10"
"#;

    std::fs::write(&vault_path, initial_content).unwrap();

    let service = VaultService::new();

    // Load TOML vault
    let mut doc = service.load_vault(&vault_path).unwrap();
    assert_eq!(doc.entries.len(), 2); // personal + personal/banking

    // Check implicit parent was created
    assert_eq!(doc.entries[0].scope_path, vec!["personal"]);
    assert_eq!(doc.entries[1].scope_path, vec!["personal", "banking"]);

    // Check custom field was preserved
    let banking_entry = doc
        .entries
        .iter()
        .find(|e| e.scope_path == vec!["personal", "banking"])
        .unwrap();
    assert!(banking_entry.custom_fields.contains_key("last_rotated"));

    // Add a new entry with custom fields
    let mut custom_fields = HashMap::new();
    custom_fields.insert(
        "priority".to_string(),
        toml::Value::String("high".to_string()),
    );
    custom_fields.insert(
        "tags".to_string(),
        toml::Value::Array(vec![
            toml::Value::String("production".to_string()),
            toml::Value::String("critical".to_string()),
        ]),
    );

    let new_entry = VaultEntry {
        scope_path: vec!["work".to_string(), "servers".to_string()],
        heading_level: 0,
        description: "Server credentials".to_string(),
        encrypted_content: "dGVzdC1lbmNyeXB0ZWQ=".to_string(),
        salt: Some(vec![1, 2, 3, 4]),
        start_line: 0,
        end_line: 0,
        custom_fields,
    };

    doc.entries.push(new_entry);

    // Save back to TOML
    service.save_vault(&doc, &vault_path).unwrap();

    // Read and verify the saved content
    let saved_content = std::fs::read_to_string(&vault_path).unwrap();

    println!("Saved TOML content:\n{}", saved_content);

    // Verify TOML structure
    assert!(saved_content.contains("version = \"v0.3\""));
    assert!(saved_content.contains("[\"personal.banking\"]"));
    assert!(saved_content.contains("last_rotated = \"2025-01-10\"")); // Custom field preserved
    assert!(saved_content.contains("[\"work.servers\"]"));
    assert!(saved_content.contains("priority = \"high\""));
    // TOML might format arrays differently
    assert!(
        saved_content.contains("tags = ")
            && saved_content.contains("production")
            && saved_content.contains("critical")
    );

    // Load again to verify round-trip
    let doc2 = service.load_vault(&vault_path).unwrap();
    assert_eq!(doc2.entries.len(), 4); // personal, personal/banking, work, work/servers
}

#[test]
fn test_markdown_format_detection() {
    let temp_dir = TempDir::new().unwrap();
    let md_path = temp_dir.path().join("vault.md");
    let toml_path = temp_dir.path().join("vault.toml");

    let service = VaultService::new();

    // Create Markdown vault
    let md_content =
        "# root <!-- vaultify v1 -->\n\n## test\n<description/>\nTest entry\n</description>\n";
    std::fs::write(&md_path, md_content).unwrap();

    // Create TOML vault
    let toml_content =
        "version = \"v0.3\"\n\n[test]\ndescription = \"Test entry\"\nencrypted = \"\"\n";
    std::fs::write(&toml_path, toml_content).unwrap();

    // Load both and verify correct parsing
    let md_doc = service.load_vault(&md_path).unwrap();
    assert_eq!(md_doc.entries.len(), 1);
    assert_eq!(md_doc.entries[0].description, "Test entry");

    let toml_doc = service.load_vault(&toml_path).unwrap();
    assert_eq!(toml_doc.entries.len(), 1);
    assert_eq!(toml_doc.entries[0].description, "Test entry");
}
