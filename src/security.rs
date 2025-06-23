//! Security features including session management and clipboard operations.

use crate::error::{Result, VaultError};
use crate::models::Session;
use copypasta::{ClipboardContext, ClipboardProvider};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;

lazy_static::lazy_static! {
    /// Global session storage.
    static ref SESSIONS: Arc<Mutex<HashMap<PathBuf, Session>>> = Arc::new(Mutex::new(HashMap::new()));
}

/// Session manager for handling vault sessions.
pub struct SessionManager;

impl SessionManager {
    /// Create a new session for a vault.
    pub fn create_session(vault_path: &Path) -> Session {
        let session = Session::new(vault_path.to_path_buf(), 5); // 5 minute timeout

        let mut sessions = SESSIONS.lock().unwrap();
        sessions.insert(vault_path.to_path_buf(), session.clone());

        session
    }

    /// Get an active session for a vault.
    pub fn get_session(vault_path: &Path) -> Option<Session> {
        let mut sessions = SESSIONS.lock().unwrap();

        if let Some(session) = sessions.get_mut(&vault_path.to_path_buf()) {
            if session.is_expired() {
                sessions.remove(&vault_path.to_path_buf());
                None
            } else {
                Some(session.clone())
            }
        } else {
            None
        }
    }

    /// Update session activity.
    pub fn update_activity(vault_path: &Path) {
        let mut sessions = SESSIONS.lock().unwrap();

        if let Some(session) = sessions.get_mut(&vault_path.to_path_buf()) {
            session.update_activity();
        }
    }

    /// Clear a session.
    pub fn clear_session(vault_path: &Path) {
        let mut sessions = SESSIONS.lock().unwrap();

        if let Some(mut session) = sessions.remove(&vault_path.to_path_buf()) {
            session.clear();
        }
    }

    /// Clear all sessions.
    pub fn clear_all_sessions() {
        let mut sessions = SESSIONS.lock().unwrap();

        for (_, mut session) in sessions.drain() {
            session.clear();
        }
    }
}

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
    use tempfile::NamedTempFile;

    #[test]
    fn test_session_lifecycle() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Create session
        let session1 = SessionManager::create_session(path);
        assert!(!session1.is_expired());

        // Get session
        let session2 = SessionManager::get_session(path);
        assert!(session2.is_some());

        // Clear session
        SessionManager::clear_session(path);
        let session3 = SessionManager::get_session(path);
        assert!(session3.is_none());
    }

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
