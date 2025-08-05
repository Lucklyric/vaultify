# vaultify

A secure, file-based password manager with hierarchical organization. Written in Rust for performance and security.

[![CI](https://github.com/Lucklyric/vaultify/actions/workflows/ci.yml/badge.svg)](https://github.com/Lucklyric/vaultify/actions/workflows/ci.yml)
[![Release](https://github.com/Lucklyric/vaultify/actions/workflows/release.yml/badge.svg)](https://github.com/Lucklyric/vaultify/actions/workflows/release.yml)
[![npm version](https://badge.fury.io/js/@lucklyric%2Fvaultify.svg)](https://www.npmjs.com/package/@lucklyric/vaultify)

## Features

- 🔐 **Per-item encryption** with Argon2id + AES-256-GCM
- 📁 **Hierarchical organization** of secrets
- 📝 **TOML-based** vault format for easy editing and versioning
- 🔍 **Fast filtering** of entries
- 📋 **Clipboard integration** with automatic clearing
- 🚀 **Interactive and CLI modes**
- 🦀 **Written in Rust** for performance and security
- 📦 **Easy installation** via npm or pre-built binaries
- 🔑 **GPG integration** for additional vault encryption
- 💾 **Automatic backups** when modifying vault files
- 🛡️ **Overwrite protection** with user prompts

## Installation

### Via npm (recommended)

```bash
# Install globally
npm install -g @lucklyric/vaultify

# Or with yarn
yarn global add @lucklyric/vaultify

# Or run directly with npx
npx @lucklyric/vaultify
```

### Pre-built binaries

Download the latest release for your platform from the [releases page](https://github.com/Lucklyric/vaultify/releases).

### From source

```bash
# Clone the repository
git clone https://github.com/Lucklyric/vaultify.git
cd vaultify

# Build with Rust
cargo build --release

# Binary will be at target/release/vaultify
```

## Quick Start

### Initialize a vault

```bash
vaultify init
```

This creates a `vault.toml` file in the current directory.

### Add a secret

```bash
# Will open your system editor for secure input
vaultify add personal/email/gmail -d "Personal Gmail account"

# From stdin
echo "my-secret-password" | vaultify add personal/email/gmail --stdin -d "Personal Gmail"
```

### List entries

```bash
# Simple list
vaultify list

# Tree view
vaultify list --tree

# Filter by scope
vaultify list personal/email
```

### Decrypt a secret

```bash
# Interactive mode - choose display format after entering password
vaultify decrypt personal/email/gmail

# Show in terminal directly
vaultify decrypt personal/email/gmail --show

# Direct to clipboard (auto-clears after 60 seconds)
vaultify decrypt personal/email/gmail --no-display --clipboard
```

### Edit an entry

```bash
vaultify edit personal/email/gmail
```

### Delete an entry

```bash
vaultify delete personal/email/gmail
```

### GPG Encryption

```bash
# Encrypt entire vault with GPG (prompts for backup and ASCII armor)
vaultify gpg-encrypt --recipient user@example.com

# Symmetric encryption (password-based)
vaultify gpg-encrypt

# Create ASCII-armored output (.asc)
vaultify gpg-encrypt --armor

# Decrypt GPG-encrypted vault
vaultify gpg-decrypt
```

### Interactive mode

Run `vaultify` without any arguments to enter interactive mode:

```bash
vaultify

vaultify> help
vaultify> list
vaultify> add work/vpn
vaultify> decrypt work/vpn
vaultify> exit
```

## Vault Format

Vaults are stored as TOML files with encrypted content:

```toml
version = "v0.3.2"
modified = "2025-01-17T10:00:00Z"

[personal]
description = "Personal accounts"
encrypted = ""
salt = ""

[personal.email]
description = "Email accounts"
encrypted = "base64-encoded-encrypted-content"
salt = "base64-encoded-salt"
```

### Key Features:
- **Insertion order preserved**: Entries maintain their original order
- **Smart group insertion**: New entries are added at the end of their group
- **Native TOML format**: Clean, readable structure with dotted key notation
- **Comment preservation**: Comments in TOML files are preserved when editing
- **Flexible parsing**: Parent entries are created automatically

## Backup System

### Automatic Backups

Vaultify automatically creates timestamped backups when modifying vault files:

- **Vault modifications**: Prompts to create backup (default: Yes)
- **GPG encryption**: Prompts to create backup (default: Yes)
- **Backup format**: `vault.toml.backup.20250721_152607`
- **GPG backup format**: `vault.toml.gpg.backup.20250721_152607`

### Overwrite Protection

- Prompts before overwriting existing files
- Applies to backups, GPG encryption, and GPG decryption
- Prevents accidental data loss

## Security

- **Encryption**: Each entry is encrypted with Argon2id + AES-256-GCM
- **Per-item salts**: Every entry has its own salt for enhanced security
- **Memory safety**: Written in Rust with automatic memory zeroing
- **No password storage**: Password required for every operation
- **Secure permissions**: Vault files are created with 600 permissions
- **Backup protection**: Automatic backups prevent data loss

## Configuration

### Environment Variables

- `VAULT_FILE`: Default vault file path
- `EDITOR` or `VISUAL`: System editor for secret input (defaults: notepad on Windows, vi on Unix)

### File Permissions

On Unix systems, vault files are automatically created with 600 permissions (read/write for owner only).

## Encryption Specification

This section provides a detailed technical specification of the encryption algorithms used by vaultify. This information allows anyone to implement a compatible decryption tool in any programming language.

### Overview

Each secret in the vault is independently encrypted using:
- **Key Derivation**: Argon2id
- **Encryption**: AES-256-GCM
- **Encoding**: Base64 for storage

### Detailed Algorithm

#### 1. Key Derivation (Argon2id)

```
Parameters:
- Memory: 65536 KB (64 MB)
- Iterations: 2
- Parallelism: 1
- Salt length: 16 bytes (128 bits)
- Key length: 32 bytes (256 bits)
```

#### 2. Encryption (AES-256-GCM)

```
Parameters:
- Key: 32 bytes from Argon2id
- Nonce: 12 bytes (96 bits) - randomly generated
- Additional Authenticated Data (AAD): None
- Tag length: 16 bytes (128 bits)
```

#### 3. Storage Format

Each encrypted entry in the TOML file contains:
- `encrypted`: Base64-encoded concatenation of [nonce || ciphertext || tag]
- `salt`: Base64-encoded 16-byte salt used for Argon2id

#### 4. Decryption Process

To decrypt an entry:

1. **Parse the TOML file** and extract the target entry's `encrypted` and `salt` fields
2. **Decode from Base64** both fields
3. **Extract components** from the encrypted data:
   - Nonce: First 12 bytes
   - Ciphertext: Bytes 12 to (length - 16)
   - Tag: Last 16 bytes
4. **Derive key** using Argon2id with the decoded salt and user's password
5. **Decrypt** using AES-256-GCM with the derived key, nonce, and tag
6. **Verify** the authentication tag - decryption fails if tag is invalid

### Example Implementation (Python)

```python
import base64
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt_vault_entry(encrypted_b64, salt_b64, password):
    # Decode from base64
    encrypted = base64.b64decode(encrypted_b64)
    salt = base64.b64decode(salt_b64)
    
    # Extract components
    nonce = encrypted[:12]
    ciphertext_with_tag = encrypted[12:]
    
    # Derive key using Argon2id
    key = low_level.hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=low_level.Type.ID
    )
    
    # Decrypt using AES-256-GCM
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    
    return plaintext.decode('utf-8')
```

### Security Considerations

1. **Per-entry encryption**: Each secret has its own salt and encryption
2. **No master key**: There's no vault-wide master password
3. **Forward secrecy**: Compromising one entry doesn't affect others
4. **Authentication**: GCM mode provides both encryption and authentication
5. **Memory hardness**: Argon2id resists GPU/ASIC attacks

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