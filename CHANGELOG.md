# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2025-10-15

###   BREAKING CHANGES

This release introduces strict scope validation to prevent vault file corruption. Invalid scope names (especially those with spaces) are now rejected with clear error messages.

**Impact**: If your existing vault contains invalid scope names, you'll need to fix them before using v0.4.0. Use the new `vaultify validate` command to check your vault.

### Added

- **Strict scope validation** with position-aware error messages
  - ASCII-only character set enforcement: `[A-Za-z0-9._-]`
  - Position tracking shows exact character location of errors (1-based indexing)
  - Multi-section error format with issue explanation, expected format, and corrected examples

- **New `validate` command** for pre-migration checking
  - `vaultify validate` - Check current vault for invalid scopes
  - `vaultify validate <path>` - Check specific vault file
  - Comprehensive reporting of all invalid entries with line numbers and suggestions
  - Exit code 0 for valid vaults, 1 for invalid

- **Automatic version upgrade**
  - Vaults are automatically upgraded from v0.3.x to v0.4.0 on save
  - Version field in vault files now shows "v0.4.0"

### Changed

- **Scope naming rules now strictly enforced**:
  - L Spaces not allowed ’ Use dots: `work.email` instead of `work email`
  - L Leading/trailing dots not allowed ’ Must start/end with alphanumeric
  - L Consecutive dots not allowed ’ Each dot must separate valid parts
  - L Hyphens/underscores at part boundaries not allowed ’ Must be within parts
  - L Non-ASCII characters not allowed ’ ASCII-only for security
  - L Unicode whitespace variants not allowed ’ Only regular trimmed spaces
  -  Maximum scope length: 256 characters

- **Enhanced error messages**
  - Parse errors now suggest invalid scope issues when TOML parsing fails
  - Error messages include position, issue description, expected format, and corrected example
  - All validation errors provide actionable guidance

### Migration Guide

**For users with valid v0.3.x vaults** (no invalid scopes):
- Simply upgrade vaultify - your vault will work seamlessly
- Version will auto-upgrade to v0.4.0 on next modification

**For users with invalid scopes** (e.g., spaces in scope names):

1. **Check your vault** before upgrading:
   ```bash
   # Using v0.3.x
   vaultify validate vault.toml
   ```

2. **If issues found**, manually edit `vault.toml`:
   - Replace spaces with dots in scope names: `[work email]` ’ `[work.email]`
   - Fix consecutive dots: `[work..email]` ’ `[work.email]`
   - Remove leading/trailing dots: `[.work]` ’ `[work]`
   - Fix hyphens at boundaries: `[work.-email]` ’ `[work.my-email]`

3. **Validate again** to confirm:
   ```bash
   vaultify validate vault.toml
   ```

4. **Upgrade vaultify**:
   ```bash
   npm install -g @lucklyric/vaultify@latest
   ```

5. **Use normally** - version will auto-upgrade to v0.4.0

**Example invalid ’ valid transformations**:
- `work email` ’ `work.email`
- `work..email` ’ `work.email`
- `.work` ’ `work`
- `work.` ’ `work`
- `work.-email` ’ `work.email` or `work.my-email`
- `café` ’ `cafe`

### Security

- **ASCII-only enforcement prevents**:
  - Homograph attacks (Unicode lookalike characters)
  - Zero-width character injection
  - Right-to-left override attacks
  - TOML injection via complex Unicode

### Technical Details

- Added `ScopeValidationError` struct with 10 error variants
- Implemented position tracking with 1-based character indexing
- Created comprehensive test suite: 42 unit tests + 16 integration tests
- All validation errors include automatic suggestion generation

## [0.3.1] - 2025-07-21

### Added
- Automatic backups with timestamped filenames
- GPG backup prompts before encryption
- ASCII armor default for GPG encryption
- Overwrite protection for backups and GPG files

### Changed
- Consistent Y/n prompt format (uppercase = default)
- GPG files now default to .asc extension (ASCII armored)

## [0.3.0] - 2025-07-21

### Added
- Interactive mode with REPL interface
- Automatic help display on startup
- Clear and exit commands
- Command history and tab completion
- Secure editor-based secret input
- GPG encryption/decryption support
- Multiline description support
- Empty credential indicators

### Changed
- Merged search into list command with optional filter
- Renamed 'copy' command to 'decrypt' for clarity
- Display mode choice after password entry
- Always prompt for clipboard copy
- Unified CLI and interactive commands
- Native TOML dotted notation

### Removed
- Session management (password required per operation)
- Markdown format support (TOML only)
- Legacy slash notation (dot notation only)

## [0.2.0] - 2025-01-15

### Added
- TOML-based vault format
- Per-item encryption with Argon2id + AES-256-GCM
- Hierarchical organization with dot notation
- Clipboard integration with auto-clear
- Tree view for listing entries
- Filter entries by scope

## [0.1.0] - 2025-01-01

### Added
- Initial release
- Basic encryption/decryption
- Command-line interface
- File-based storage

[0.4.0]: https://github.com/Lucklyric/vaultify/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/Lucklyric/vaultify/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Lucklyric/vaultify/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Lucklyric/vaultify/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Lucklyric/vaultify/releases/tag/v0.1.0
