#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// Get the path to the binary
const binaryPath = path.join(__dirname, 'bin', process.platform === 'win32' ? 'vault.exe' : 'vault-bin');

// Check if binary exists
if (!fs.existsSync(binaryPath)) {
  console.error('vault-cli binary not found. Running postinstall...');
  try {
    require('child_process').execSync('node ' + path.join(__dirname, 'install.js'), {
      stdio: 'inherit',
      cwd: __dirname
    });
  } catch (e) {
    console.error('Failed to install vault-cli binary');
    process.exit(1);
  }
}

// Spawn the binary with all arguments
const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: 'inherit',
});

// Forward the exit code
child.on('close', (code) => {
  process.exit(code);
});

// Handle spawn errors
child.on('error', (err) => {
  console.error('Failed to run vault-cli:', err.message);
  process.exit(1);
});