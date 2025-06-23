# vault-cli

A secure, file-based password manager with hierarchical organization. Written in Rust for performance and security.

[![CI](https://github.com/Lucklyric/vault-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/Lucklyric/vault-cli/actions/workflows/ci.yml)
[![Release](https://github.com/Lucklyric/vault-cli/actions/workflows/release.yml/badge.svg)](https://github.com/Lucklyric/vault-cli/actions/workflows/release.yml)
[![npm version](https://badge.fury.io/js/@vault-cli%2Fvault.svg)](https://www.npmjs.com/package/@vault-cli/vault)

## Features

- 🔐 **Per-item encryption** with Argon2id + AES-256-GCM
- 📁 **Hierarchical organization** of secrets
- 📝 **Markdown-based** vault format for easy versioning
- 🔍 **Fast search** across entries
- 📋 **Clipboard integration** with automatic clearing
- 🚀 **Interactive and CLI modes**
- 🦀 **Written in Rust** for performance and security
- 📦 **Easy installation** via npm, homebrew, or pre-built binaries

## Installation

### Via npm (recommended)

```bash
# Install globally
npm install -g @vault-cli/vault

# Or with yarn
yarn global add @vault-cli/vault

# Or run directly with npx
npx @vault-cli/vault
```

### Pre-built binaries

Download the latest release for your platform from the [releases page](https://github.com/Lucklyric/vault-cli/releases).

### From source

```bash
# Clone the repository
git clone https://github.com/Lucklyric/vault-cli.git
cd vault-cli/vault-cli-rust

# Build with Rust
cargo build --release

# Binary will be at target/release/vault
```

## Quick Start

### Initialize a vault

```bash
vault init
```

This creates a `vault.md` file in the current directory.

### Add a secret

```bash
# Interactive mode (recommended for passwords)
vault add personal/email/gmail -d "Personal Gmail account"

# From stdin
echo "my-secret-password" | vault add personal/email/gmail --stdin -d "Personal Gmail"

# Using editor
vault add personal/email/gmail --editor -d "Personal Gmail"
```

### List entries

```bash
# Simple list
vault list

# Tree view
vault list --tree

# Filter by scope
vault list personal/email
```

### Decrypt a secret

```bash
# Display in terminal
vault decrypt personal/email/gmail --show

# Copy to clipboard (auto-clears after 10 seconds)
vault decrypt personal/email/gmail --clipboard

# Custom timeout
vault decrypt personal/email/gmail --clipboard --timeout 30
```

### Search entries

```bash
# Search in scope names
vault search gmail

# Search in descriptions
vault search "email account" --description

# Case sensitive search
vault search Gmail --case-sensitive
```

### Interactive mode

Run `vault` without any arguments to enter interactive mode:

```bash
vault

vault> help
vault> list
vault> add work/vpn
vault> show work/vpn
vault> exit
```

## Vault Format

Vaults are stored as markdown files with encrypted content:

```markdown
# root <!-- vault-cli v1 -->

## personal
<description/>
Personal accounts
</description>
<encrypted></encrypted>

### personal/email
<description/>
Email accounts
</description>
<encrypted salt="base64-encoded-salt">
base64-encoded-encrypted-content
</encrypted>
```

## Security

- **Encryption**: Each entry is encrypted with Argon2id + AES-256-GCM
- **Per-item salts**: Every entry has its own salt for enhanced security
- **Memory safety**: Written in Rust with automatic memory zeroing
- **No key storage**: Master password is never stored, only session keys
- **Secure permissions**: Vault files are created with 600 permissions

### Encryption Details

- **Key Derivation**: Argon2id with 64MB memory, 2 iterations
- **Encryption**: AES-256-GCM with 96-bit nonces
- **Salt**: 128-bit per-item random salts
- **Authentication**: GCM provides authenticated encryption

## Configuration

### Environment Variables

- `VAULT_FILE`: Default vault file path
- `EDITOR`: Editor to use for `--editor` mode (default: nano)

### File Permissions

On Unix systems, vault files are automatically created with 600 permissions (read/write for owner only).

## Development

### Building

```bash
cd vault-cli-rust
cargo build --release
```

### Testing

```bash
cargo test
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.