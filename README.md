# vault-cli

A secure, file-based password manager with hierarchical organization. Written in Rust for performance and security.

[![CI](https://github.com/Lucklyric/vault-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/Lucklyric/vault-cli/actions/workflows/ci.yml)
[![Release](https://github.com/Lucklyric/vault-cli/actions/workflows/release.yml/badge.svg)](https://github.com/Lucklyric/vault-cli/actions/workflows/release.yml)
[![npm version](https://badge.fury.io/js/@lucklyric%2Fvault-cli.svg)](https://www.npmjs.com/package/@lucklyric/vault-cli)

## Features

- 🔐 **Per-item encryption** with Argon2id + AES-256-GCM
- 📁 **Hierarchical organization** of secrets
- 📝 **Markdown-based** vault format for easy versioning
- 🔍 **Fast filtering** of entries
- 📋 **Clipboard integration** with automatic clearing
- 🚀 **Interactive and CLI modes**
- 🦀 **Written in Rust** for performance and security
- 📦 **Easy installation** via npm or pre-built binaries
- 🔑 **GPG integration** for additional vault encryption

## Installation

### Via npm (recommended)

```bash
# Install globally
npm install -g @lucklyric/vault-cli

# Or with yarn
yarn global add @lucklyric/vault-cli

# Or run directly with npx
npx @lucklyric/vault-cli
```

### Pre-built binaries

Download the latest release for your platform from the [releases page](https://github.com/Lucklyric/vault-cli/releases).

### From source

```bash
# Clone the repository
git clone https://github.com/Lucklyric/vault-cli.git
cd vault-cli

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
# Will open your system editor for secure input
vault add personal/email/gmail -d "Personal Gmail account"

# From stdin
echo "my-secret-password" | vault add personal/email/gmail --stdin -d "Personal Gmail"
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
# Interactive mode - choose display format after entering password
vault decrypt personal/email/gmail

# Show in terminal directly
vault decrypt personal/email/gmail --show

# Direct to clipboard (auto-clears after 60 seconds)
vault decrypt personal/email/gmail --no-display --clipboard
```

### Edit an entry

```bash
vault edit personal/email/gmail
```

### Delete an entry

```bash
vault delete personal/email/gmail
```

### GPG Encryption

```bash
# Encrypt entire vault with GPG
vault gpg-encrypt --recipient user@example.com

# Decrypt GPG-encrypted vault
vault gpg-decrypt
```

### Interactive mode

Run `vault` without any arguments to enter interactive mode:

```bash
vault

vault> help
vault> list
vault> add work/vpn
vault> decrypt work/vpn
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
- **No password storage**: Password required for every operation
- **Secure permissions**: Vault files are created with 600 permissions

### Encryption Details

- **Key Derivation**: Argon2id with 64MB memory, 2 iterations
- **Encryption**: AES-256-GCM with 96-bit nonces
- **Salt**: 128-bit per-item random salts
- **Authentication**: GCM provides authenticated encryption

## Configuration

### Environment Variables

- `VAULT_FILE`: Default vault file path
- `EDITOR` or `VISUAL`: System editor for secret input (defaults: notepad on Windows, vi on Unix)

### File Permissions

On Unix systems, vault files are automatically created with 600 permissions (read/write for owner only).

## Development

### Building

```bash
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