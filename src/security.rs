//! Security features including clipboard operations.

use crate::error::{Result, VaultError};
use copypasta::{ClipboardContext, ClipboardProvider};
use std::time::Duration;
use tokio::time::sleep;

/// Clipboard manager for secure clipboard operations.
pub struct ClipboardManager;

impl ClipboardManager {
    /// Copy text to clipboard with automatic clearing after timeout.
    pub async fn copy_with_timeout(text: &str, timeout_secs: u64) -> Result<()> {
        // Copy to clipboard
        Self::copy(text)?;

        // Spawn async task to clear after timeout
        let text_to_clear = text.to_string();
        tokio::spawn(async move {
            sleep(Duration::from_secs(timeout_secs)).await;

            // Check if clipboard still contains our text
            if let Ok(current) = Self::get_contents() {
                if current == text_to_clear {
                    let _ = Self::clear();
                }
            }
        });

        Ok(())
    }

    /// Copy text to clipboard.
    pub fn copy(text: &str) -> Result<()> {
        let mut ctx = ClipboardContext::new().map_err(|_| VaultError::ClipboardFailed)?;

        ctx.set_contents(text.to_string())
            .map_err(|_| VaultError::ClipboardFailed)?;

        Ok(())
    }

    /// Get clipboard contents.
    pub fn get_contents() -> Result<String> {
        let mut ctx = ClipboardContext::new().map_err(|_| VaultError::ClipboardFailed)?;

        ctx.get_contents().map_err(|_| VaultError::ClipboardFailed)
    }

    /// Clear clipboard.
    pub fn clear() -> Result<()> {
        Self::copy("")
    }
}

/// Check if running with appropriate permissions.
pub fn check_permissions() -> Vec<String> {
    let mut warnings = Vec::new();

    #[cfg(unix)]
    {
        // Check if running as root
        if unsafe { libc::geteuid() } == 0 {
            warnings.push("Running as root is not recommended".to_string());
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_operations() {
        // Note: This test might fail in CI environments without clipboard access
        if std::env::var("CI").is_ok() {
            return;
        }

        let test_text = "test_clipboard_content";

        // Copy to clipboard
        assert!(ClipboardManager::copy(test_text).is_ok());

        // Read from clipboard
        if let Ok(content) = ClipboardManager::get_contents() {
            assert_eq!(content, test_text);
        }

        // Clear clipboard
        assert!(ClipboardManager::clear().is_ok());
    }
}
