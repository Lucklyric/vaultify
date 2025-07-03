//! Secure temporary file handling for sensitive data.

use crate::error::{Result, VaultError};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::Zeroize;

/// Prefix for vaultify temporary files
const TEMP_FILE_PREFIX: &str = "vaultify-edit-";

/// Get the secure temp directory for vaultify
fn get_secure_temp_dir() -> Result<PathBuf> {
    let temp_dir = std::env::temp_dir().join("vaultify-secure");

    // Create directory if it doesn't exist
    if !temp_dir.exists() {
        fs::create_dir_all(&temp_dir)?;
    }

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&temp_dir)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&temp_dir, perms)?;
    }

    Ok(temp_dir)
}

/// Clean up any leftover temporary files from previous sessions
pub fn cleanup_old_temp_files() -> Result<()> {
    let temp_dir = get_secure_temp_dir()?;

    if temp_dir.exists() {
        // Read directory and remove old temp files
        for entry in fs::read_dir(&temp_dir)? {
            let entry = entry?;
            let path = entry.path();

            if let Some(filename) = path.file_name() {
                if let Some(filename_str) = filename.to_str() {
                    if filename_str.starts_with(TEMP_FILE_PREFIX) {
                        // Attempt to securely wipe the file content first
                        if let Ok(mut content) = fs::read(&path) {
                            content.zeroize();
                            let _ = fs::write(&path, &content);
                        }
                        // Remove the file
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Secure temporary file for editing sensitive data
pub struct SecureTempFile {
    path: PathBuf,
    cleaned: bool,
}

impl SecureTempFile {
    /// Create a new secure temporary file
    pub fn new() -> Result<Self> {
        let temp_dir = get_secure_temp_dir()?;

        // Create a named temp file in our secure directory
        let temp_file = tempfile::Builder::new()
            .prefix(TEMP_FILE_PREFIX)
            .suffix(".txt")
            .tempfile_in(&temp_dir)?;

        // Keep the file but we'll manage it ourselves
        let (_file, path_owned) = temp_file
            .keep()
            .map_err(|e| VaultError::Other(format!("Failed to persist temp file: {}", e)))?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path_owned)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&path_owned, perms)?;
        }

        Ok(Self {
            path: path_owned,
            cleaned: false,
        })
    }

    /// Get the path to the temporary file
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write initial content to the file
    pub fn write_initial(&self, content: &str) -> Result<()> {
        fs::write(&self.path, content)?;
        Ok(())
    }

    /// Open the file in the user's editor and return the content
    pub fn edit_with_editor(&self) -> Result<String> {
        // Determine editor
        let editor = std::env::var("EDITOR")
            .or_else(|_| std::env::var("VISUAL"))
            .unwrap_or_else(|_| {
                if cfg!(windows) {
                    "notepad".to_string()
                } else {
                    "vi".to_string()
                }
            });

        // Open editor
        let status = Command::new(&editor)
            .arg(&self.path)
            .status()
            .map_err(|e| {
                VaultError::Other(format!("Failed to launch editor '{}': {}", editor, e))
            })?;

        if !status.success() {
            return Err(VaultError::Other("Editor exited with error".to_string()));
        }

        // Read content
        let content = fs::read_to_string(&self.path)?;
        Ok(content)
    }

    /// Securely clean up the temporary file
    pub fn cleanup(&mut self) -> Result<()> {
        if !self.cleaned && self.path.exists() {
            // Read the file content
            if let Ok(mut content) = fs::read(&self.path) {
                // Overwrite with zeros
                content.zeroize();
                fs::write(&self.path, &content)?;

                // Overwrite with random data
                let random_data: Vec<u8> =
                    (0..content.len()).map(|_| rand::random::<u8>()).collect();
                fs::write(&self.path, &random_data)?;
            }

            // Remove the file
            fs::remove_file(&self.path)?;
            self.cleaned = true;
        }
        Ok(())
    }
}

impl Drop for SecureTempFile {
    fn drop(&mut self) {
        // Best effort cleanup in destructor
        let _ = self.cleanup();
    }
}

/// Get secret content using external editor
pub fn get_secret_from_editor(initial_content: Option<&str>) -> Result<String> {
    let mut temp_file = SecureTempFile::new()?;

    // Write initial content if provided
    if let Some(content) = initial_content {
        temp_file.write_initial(content)?;
    } else {
        // Write instructions
        temp_file.write_initial(
            "# Enter your secret below this line\n\
             # Lines starting with # will be removed\n\
             # Save and exit when done\n\n",
        )?;
    }

    // Edit with editor
    let content = temp_file.edit_with_editor()?;

    // Clean up immediately
    temp_file.cleanup()?;

    // Process content - remove comment lines and trim
    let processed: String = content
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();

    if processed.is_empty() {
        return Err(VaultError::Other("No content entered".to_string()));
    }

    Ok(processed)
}
