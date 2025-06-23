#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');

// Get the path to the binary
const binaryPath = path.join(__dirname, 'bin', process.platform === 'win32' ? 'vault.exe' : 'vault');

// Spawn the binary with all arguments
const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: 'inherit',
});

// Forward the exit code
child.on('close', (code) => {
  process.exit(code);
});