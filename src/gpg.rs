//! GPG integration for encrypting/decrypting vault files.

use crate::error::{Result, VaultError};
use crate::utils;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// GPG operations for vault files.
pub struct GpgOperations;

impl GpgOperations {
    /// Check if GPG is available on the system.
    pub fn check_gpg_available() -> Result<()> {
        let output = Command::new("gpg")
            .arg("--version")
            .output()
            .map_err(|e| VaultError::Other(format!("GPG not found: {e}. Please install GPG.")))?;

        if !output.status.success() {
            return Err(VaultError::Other("GPG command failed".to_string()));
        }

        Ok(())
    }

    /// Encrypt a vault file using GPG.
    pub fn encrypt_vault(
        vault_path: &Path,
        recipient: Option<&str>,
        armor: bool,
    ) -> Result<PathBuf> {
        Self::check_gpg_available()?;

        // Ensure vault file exists
        if !vault_path.exists() {
            return Err(VaultError::VaultNotFound(vault_path.to_path_buf()));
        }

        // Create output path based on original file extension
        let output_path = if armor {
            vault_path.with_extension("toml.asc")
        } else {
            vault_path.with_extension("toml.gpg")
        };

        // Check if output already exists and prompt for overwrite
        if output_path.exists()
            && !utils::prompt_yes_no(
                &format!(
                    "GPG encrypted file {} already exists. Overwrite?",
                    output_path.display()
                ),
                true,
            )?
        {
            return Err(VaultError::Cancelled);
        }

        // Remove this duplicate backup prompt - backup is already handled in save_vault

        // Build GPG command
        let mut cmd = Command::new("gpg");

        // Always use symmetric encryption if no recipient
        if let Some(recipient) = recipient {
            cmd.arg("--encrypt").arg("--recipient").arg(recipient);
        } else {
            cmd.arg("--symmetric");
        }

        if armor {
            cmd.arg("--armor");
        }

        cmd.arg("--output").arg(&output_path).arg(vault_path);

        // Execute encryption interactively
        let mut child = cmd
            .spawn()
            .map_err(|e| VaultError::Other(format!("Failed to run GPG: {e}")))?;

        let status = child
            .wait()
            .map_err(|e| VaultError::Other(format!("Failed to wait for GPG: {e}")))?;

        if !status.success() {
            return Err(VaultError::Other("GPG encryption failed".to_string()));
        }

        Ok(output_path)
    }

    /// Decrypt a GPG-encrypted vault file.
    pub fn decrypt_vault(encrypted_path: &Path, output_path: Option<&Path>) -> Result<PathBuf> {
        Self::check_gpg_available()?;

        // Ensure encrypted file exists
        if !encrypted_path.exists() {
            return Err(VaultError::VaultNotFound(encrypted_path.to_path_buf()));
        }

        // Determine output path
        let output = if let Some(path) = output_path {
            path.to_path_buf()
        } else {
            // Remove .gpg or .asc extension to get original filename
            let file_name = encrypted_path
                .file_name()
                .ok_or_else(|| VaultError::Other("Invalid encrypted file name".to_string()))?
                .to_string_lossy();

            // Handle both vault.toml.gpg and vault.toml.asc formats
            let output_name = if file_name.ends_with(".gpg") {
                file_name.trim_end_matches(".gpg")
            } else if file_name.ends_with(".asc") {
                file_name.trim_end_matches(".asc")
            } else {
                return Err(VaultError::Other(
                    "Encrypted file must have .gpg or .asc extension".to_string(),
                ));
            };

            encrypted_path.with_file_name(output_name)
        };

        // Check if output already exists and prompt for overwrite
        if output.exists()
            && !utils::prompt_yes_no(
                &format!(
                    "Output file {} already exists. Overwrite?",
                    output.display()
                ),
                true,
            )?
        {
            return Err(VaultError::Cancelled);
        }

        // Build GPG command
        let mut cmd = Command::new("gpg");
        cmd.arg("--decrypt")
            .arg("--output")
            .arg(&output)
            .arg(encrypted_path);

        // Execute decryption interactively
        let mut child = cmd
            .spawn()
            .map_err(|e| VaultError::Other(format!("Failed to run GPG: {e}")))?;

        let status = child
            .wait()
            .map_err(|e| VaultError::Other(format!("Failed to wait for GPG: {e}")))?;

        if !status.success() {
            return Err(VaultError::Other("GPG decryption failed".to_string()));
        }

        Ok(output)
    }

    /// List available GPG keys.
    pub fn list_keys() -> Result<Vec<String>> {
        Self::check_gpg_available()?;

        let output = Command::new("gpg")
            .args(["--list-keys", "--with-colons"])
            .output()
            .map_err(|e| VaultError::Other(format!("Failed to list GPG keys: {e}")))?;

        if !output.status.success() {
            return Err(VaultError::Other("Failed to list GPG keys".to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut keys = Vec::new();

        for line in stdout.lines() {
            if line.starts_with("uid:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() > 9 {
                    keys.push(parts[9].to_string());
                }
            }
        }

        Ok(keys)
    }

    /// Check if a file is GPG encrypted.
    pub fn is_gpg_file(path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            ext_str == "gpg" || ext_str == "asc"
        } else {
            false
        }
    }

    /// Create a backup of the vault file before GPG operations.
    pub fn backup_vault(vault_path: &Path) -> Result<PathBuf> {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let file_name = vault_path
            .file_name()
            .ok_or_else(|| VaultError::Other("Invalid file name".to_string()))?
            .to_string_lossy();

        // For GPG files, create backup as vault.toml.gpg.backup.timestamp
        // For regular files, create backup as vault.toml.backup.timestamp
        let backup_path = if file_name.ends_with(".gpg") || file_name.ends_with(".asc") {
            vault_path.with_file_name(format!("{file_name}.backup.{timestamp}"))
        } else {
            // When encrypting a regular file, assume it will become .gpg
            vault_path.with_file_name(format!("{file_name}.gpg.backup.{timestamp}"))
        };

        fs::copy(vault_path, &backup_path)
            .map_err(|e| VaultError::Other(format!("Failed to create backup: {e}")))?;

        Ok(backup_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_gpg_file() {
        assert!(GpgOperations::is_gpg_file(Path::new("vault.toml.gpg")));
        assert!(GpgOperations::is_gpg_file(Path::new("vault.toml.asc")));
        assert!(!GpgOperations::is_gpg_file(Path::new("vault.toml")));
    }

    #[test]
    fn test_check_gpg_available() {
        // This test might fail on systems without GPG
        if std::env::var("CI").is_ok() {
            return;
        }

        // Just check that the function runs without panicking
        let _ = GpgOperations::check_gpg_available();
    }
}
