#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// Get the path to the binary
const binaryPath = path.join(__dirname, 'bin', process.platform === 'win32' ? 'vaultify.exe' : 'vaultify');

// Check if binary exists
if (!fs.existsSync(binaryPath)) {
  console.error('vaultify binary not found. Running postinstall...');
  try {
    require('child_process').execSync('node ' + path.join(__dirname, 'install.js'), {
      stdio: 'inherit',
      cwd: __dirname
    });
  } catch (e) {
    console.error('Failed to install vaultify binary');
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
  console.error('Failed to run vaultify:', err.message);
  process.exit(1);
});