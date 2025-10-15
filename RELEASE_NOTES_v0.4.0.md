# Release Notes: vaultify v0.4.0

**Release Date**: October 15, 2025

## 🚨 Breaking Changes

This is a **BREAKING CHANGE** release that introduces strict scope validation to fix a critical data integrity bug. Invalid scope names (especially those containing spaces) will now be rejected with clear error messages.

### What This Means for You

- ✅ **If your vault has only valid scopes**: Seamless upgrade, no action required
- ⚠️ **If your vault has invalid scopes**: You'll need to fix them before upgrading (see Migration Guide below)

### Why This Change?

Previously, vaultify allowed invalid scope names like `work email` (with spaces) to be created. This caused vault file corruption because TOML format doesn't support spaces in section names without quotes, and vaultify uses native TOML dotted notation for cleaner, more maintainable vault files.

This release enforces strict validation at entry time, preventing corruption before it happens.

## 🎯 Key Features

### 1. Strict Scope Validation with Position-Aware Errors

**Before v0.4.0**:
```
Error: Invalid TOML format at line 5
```

**After v0.4.0**:
```
Invalid scope 'work email' at position 5: found space character

Issue: Spaces are not supported in scope names
Expected format: Use dots to separate parts

Example: 'work.email' (instead of 'work email')
```

**Features**:
- 🎯 Exact position tracking (1-based character indexing)
- 📝 Multi-section error format with issue explanation
- ✅ Corrected examples in every error message
- 🔍 Comprehensive validation rules enforced

### 2. New `validate` Command

Pre-migration safety check to audit your vault before upgrading:

```bash
# Check current directory vault
vaultify validate

# Check specific file
vaultify validate path/to/vault.toml
```

**Output** (if issues found):
```
✗ Found 2 invalid scopes in vault file:

Line 5: [work email]
  Invalid scope 'work email' at position 5: found space character
  Suggestion: Use 'work.email' instead

Line 12: [test..scope]
  Invalid scope 'test..scope' at position 5-6: found consecutive dots
  Suggestion: Use 'test.scope' instead

Fix these issues before using with vaultify v0.4.0
```

**Exit codes**:
- `0` - Vault is valid
- `1` - Vault has invalid scopes

Perfect for scripts and CI/CD pipelines!

### 3. Automatic Version Upgrade

Vaults are automatically upgraded from v0.3.x to v0.4.0 when saved. No manual intervention needed for valid vaults.

**Before**: `version = "v0.3.1"`
**After**: `version = "v0.4.0"`

## 📋 Scope Naming Rules (Enforced)

### ✅ Valid Characters

**Allowed**:
- Letters: `A-Z`, `a-z`
- Numbers: `0-9`
- Separators: `.` (dot)
- Special: `-` (hyphen), `_` (underscore)

**ASCII Only**: No Unicode characters for security reasons.

### ✅ Structure Rules

| Rule | Invalid | Valid |
|------|---------|-------|
| Use dots to separate parts | `work email` | `work.email` |
| No leading dots | `.work` | `work` |
| No trailing dots | `work.` | `work` |
| No consecutive dots | `work..email` | `work.email` |
| Hyphens/underscores within parts only | `work.-email` | `work.my-email` |
| ASCII only | `café` | `cafe` |
| Max 256 characters | `very...long...` | `reasonable.length` |

### Examples

**✅ Valid Scopes**:
```
work
personal.email
company.projects.client-a.api-key
my-work.my-email
project_x.api_key.production
server1.database.password
```

**❌ Invalid Scopes**:
```
work email          → work.email
work..email         → work.email
.work               → work
work.               → work
work.-email         → work.my-email
café.password       → cafe.password
```

## 🔒 Security Improvements

ASCII-only enforcement prevents:
- **Homograph attacks**: Unicode lookalike characters (Cyrillic 'а' vs Latin 'a')
- **Zero-width characters**: Invisible characters that could hide malicious content
- **RTL override attacks**: Right-to-left Unicode controls that confuse display
- **TOML injection**: Complex Unicode that might bypass parsing

## 📖 Migration Guide

### For Users with Valid Vaults (Most Users)

Your vault likely has valid scopes already. Simply upgrade:

```bash
npm install -g @lucklyric/vaultify@latest
```

Your vault will automatically upgrade to v0.4.0 on next modification.

### For Users with Invalid Scopes

**Step 1**: Check your vault (using v0.3.x before upgrading):
```bash
vaultify validate vault.toml
```

**Step 2**: If issues found, manually edit `vault.toml`:

Open the file in a text editor and fix the reported issues:
- `[work email]` → `[work.email]`
- `[test..scope]` → `[test.scope]`
- `[.work]` → `[work]`
- `[work.-email]` → `[work.email]` or `[work.my-email]`

**Step 3**: Validate again:
```bash
vaultify validate vault.toml
```

**Step 4**: Upgrade vaultify:
```bash
npm install -g @lucklyric/vaultify@latest
```

**Step 5**: Use normally - version auto-upgrades to v0.4.0

### Common Transformations

| Before (Invalid) | After (Valid) | Reason |
|-----------------|---------------|---------|
| `work email` | `work.email` | Spaces not allowed |
| `work..email` | `work.email` | Consecutive dots |
| `.work` | `work` | Leading dot |
| `work.` | `work` | Trailing dot |
| `work.-email` | `work.email` | Hyphen at boundary |
| `_test` | `test` or `my_test` | Underscore at boundary |
| `café` | `cafe` | Non-ASCII character |

## 🧪 Testing

This release includes comprehensive test coverage:
- **42 unit tests** for validation logic
- **16 integration tests** for CLI/validate command
- **87 total tests** passing
- **Zero clippy warnings**
- **100% code formatting compliance**

All validation rules are thoroughly tested with edge cases.

## 📊 Technical Details

### Implementation

- **New error types**: `ScopeValidationError` with 10 error variants
- **Position tracking**: Character-level position tracking with 1-based indexing
- **Two-phase validation**: Full TOML parse + regex fallback for best-effort comprehensive reporting
- **Automatic suggestions**: Every error includes a corrected example

### Performance

- Validation: <0.1ms for typical scopes (<100 chars)
- Validate command: <100ms for 1000-entry vaults
- Zero performance regression for existing operations

### Breaking Change Details

**Impact Level**: Medium
- **Existing valid vaults**: No impact, seamless upgrade
- **Vaults with invalid scopes**: Require manual fixing (clear error messages guide users)

**Rationale**: Preventing data integrity issues is more important than backward compatibility for invalid data.

## 🔗 Resources

- **Full CHANGELOG**: [CHANGELOG.md](CHANGELOG.md#040---2025-10-15)
- **Scope Naming Guide**: [README.md - Scope Naming Rules](README.md#scope-naming-rules-v040)
- **Issue Tracker**: [GitHub Issues](https://github.com/Lucklyric/vaultify/issues)
- **npm Package**: [@lucklyric/vaultify](https://www.npmjs.com/package/@lucklyric/vaultify)

## 📝 Upgrading

### Via npm
```bash
npm install -g @lucklyric/vaultify@latest
```

### Via yarn
```bash
yarn global add @lucklyric/vaultify@latest
```

### Verify installation
```bash
vaultify --version
# Should show: vaultify 0.4.0
```

## 💬 Feedback & Support

Found a bug? Have a question? Suggestions for improvement?

- **Report issues**: [GitHub Issues](https://github.com/Lucklyric/vaultify/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Lucklyric/vaultify/discussions)
- **Security issues**: Email security concerns privately

## 🙏 Credits

This release was made possible by extensive testing, validation, and feedback. Special thanks to all contributors and users who reported scope validation issues.

---

**vaultify v0.4.0** - Secure, validated, reliable credential management.
