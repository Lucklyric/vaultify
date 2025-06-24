# @lucklyric/vault-cli

A secure command-line password manager with hierarchical organization. Pre-compiled binaries for Linux, macOS, and Windows.

## Installation

```bash
# Install globally
npm install -g @lucklyric/vault-cli

# Or with yarn
yarn global add @lucklyric/vault-cli

# Or run directly with npx
npx @lucklyric/vault-cli
```

The installer will automatically download the appropriate pre-built binary for your platform.

## Usage

### Initialize a vault

```bash
vault init
```

### Add a secret

```bash
# Will open your system editor for secure input
vault add personal/email -d "Personal email account"

# Or read from stdin
echo "my-secret" | vault add personal/api-key --stdin
```

### List entries

```bash
# Simple list
vault list

# Tree view
vault list --tree

# Filter entries
vault list gmail
```

### Decrypt a secret

```bash
# Interactive mode - choose display format after entering password
vault decrypt personal/email

# Direct to clipboard (auto-clears after 60 seconds)
vault decrypt personal/email --no-display --clipboard

# Show in terminal
vault decrypt personal/email --show
```

### Edit an entry

```bash
vault edit personal/email
```

### Delete an entry

```bash
vault delete personal/email
```

### Interactive mode

```bash
# Run without arguments for interactive mode
vault
```

### GPG Encryption

```bash
# Encrypt entire vault with GPG
vault gpg-encrypt --recipient user@example.com

# Decrypt GPG-encrypted vault
vault gpg-decrypt
```

## Features

- 🔐 **Per-item encryption** - Each secret has its own password (no master password)
- 🔒 **Strong crypto** - Argon2id + AES-256-GCM encryption
- 📁 **Hierarchical organization** - Organize secrets in tree structure
- 📋 **Smart clipboard** - Auto-clear after 60 seconds
- 🖥️ **Editor integration** - Use your preferred editor for secret input
- 🔍 **Fast search** - Filter by scope or description
- 🗝️ **GPG support** - Additional encryption layer for entire vault
- 🦀 **Rust powered** - Fast, secure, and memory-safe

## Security

- Each entry is individually encrypted with its own salt
- Password required for every operation (no session caching)
- Secure temporary files for editor input
- Automatic memory zeroization
- File permissions enforced (600 on Unix)

## Supported Platforms

Pre-built binaries are available for:
- Linux (x64)
- macOS (x64, arm64)
- Windows (x64)

## Documentation

For full documentation and source code, visit [https://github.com/Lucklyric/vault-cli](https://github.com/Lucklyric/vault-cli)

## License

Apache-2.0