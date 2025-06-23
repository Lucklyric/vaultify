# @vault-cli/vault

A secure password manager with hierarchical organization.

## Installation

```bash
# Install globally
npm install -g @vault-cli/vault

# Or with yarn
yarn global add @vault-cli/vault

# Or run directly with npx
npx @vault-cli/vault
```

## Usage

### Initialize a vault

```bash
vault init
```

### Add a secret

```bash
vault add personal/email -d "Personal email account"
```

### List entries

```bash
vault list --tree
```

### Decrypt a secret

```bash
vault decrypt personal/email --clipboard
```

### Search entries

```bash
vault search gmail
```

### Interactive mode

```bash
vault
```

## Features

- 🔐 Per-item encryption with Argon2id + AES-256-GCM
- 📁 Hierarchical organization of secrets
- 🔍 Fast search across entries
- 📋 Clipboard integration with auto-clear
- 🚀 Interactive and CLI modes
- 🦀 Written in Rust for performance and security

## Documentation

For full documentation, visit [https://github.com/Lucklyric/vault-cli](https://github.com/Lucklyric/vault-cli)

## License

Apache-2.0