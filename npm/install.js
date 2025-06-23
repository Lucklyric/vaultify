#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const https = require('https');
const tar = require('tar');

const REPO = 'Lucklyric/vault-cli';
const VERSION = require('./package.json').version;

// Map Node's platform names to Rust's target triple components
const PLATFORM_MAP = {
  darwin: 'apple-darwin',
  linux: 'unknown-linux-gnu',
  win32: 'pc-windows-msvc',
};

const ARCH_MAP = {
  x64: 'x86_64',
  arm64: 'aarch64',
};

function getPlatform() {
  const platform = PLATFORM_MAP[process.platform];
  if (!platform) {
    throw new Error(`Unsupported platform: ${process.platform}`);
  }
  return platform;
}

function getArch() {
  const arch = ARCH_MAP[process.arch];
  if (!arch) {
    throw new Error(`Unsupported architecture: ${process.arch}`);
  }
  return arch;
}

function getBinaryName() {
  const platform = getPlatform();
  const arch = getArch();
  return `vault-${arch}-${platform}`;
}

function getBinaryUrl() {
  const binaryName = getBinaryName();
  return `https://github.com/${REPO}/releases/download/v${VERSION}/${binaryName}.tar.gz`;
}

function downloadBinary(url, dest) {
  return new Promise((resolve, reject) => {
    console.log(`Downloading ${url}...`);
    
    https.get(url, (response) => {
      if (response.statusCode === 302 || response.statusCode === 301) {
        // Follow redirect
        return downloadBinary(response.headers.location, dest).then(resolve).catch(reject);
      }
      
      if (response.statusCode !== 200) {
        reject(new Error(`Failed to download binary: ${response.statusCode}`));
        return;
      }
      
      const file = fs.createWriteStream(dest);
      response.pipe(file);
      
      file.on('finish', () => {
        file.close(() => resolve());
      });
    }).on('error', reject);
  });
}

async function extractBinary(tarPath, destDir) {
  console.log('Extracting binary...');
  await tar.extract({
    file: tarPath,
    cwd: destDir,
  });
}

async function install() {
  try {
    const binDir = path.join(__dirname, 'bin');
    
    // Create bin directory
    if (!fs.existsSync(binDir)) {
      fs.mkdirSync(binDir, { recursive: true });
    }
    
    // Check if binary already exists
    const binaryPath = path.join(binDir, process.platform === 'win32' ? 'vault.exe' : 'vault');
    if (fs.existsSync(binaryPath)) {
      console.log('Binary already installed.');
      return;
    }
    
    // Download binary
    const url = getBinaryUrl();
    const tarPath = path.join(binDir, 'vault.tar.gz');
    
    try {
      await downloadBinary(url, tarPath);
      await extractBinary(tarPath, binDir);
      
      // Clean up tar file
      fs.unlinkSync(tarPath);
      
      // Make binary executable on Unix
      if (process.platform !== 'win32') {
        fs.chmodSync(binaryPath, 0o755);
      }
      
      console.log('vault-cli installed successfully!');
    } catch (error) {
      // Fallback: try to build from source
      console.error('Failed to download pre-built binary:', error.message);
      console.log('Attempting to build from source...');
      
      // Check if Rust is installed
      try {
        execSync('cargo --version', { stdio: 'ignore' });
      } catch (e) {
        throw new Error('Rust is not installed. Please install Rust from https://rustup.rs/');
      }
      
      // Build from source
      const projectRoot = path.join(__dirname, '..');
      const rustDir = path.join(projectRoot, 'vault-cli-rust');
      
      if (!fs.existsSync(rustDir)) {
        throw new Error('Source code not found. Please install from npm or clone the repository.');
      }
      
      console.log('Building vault-cli from source...');
      execSync('cargo build --release', {
        cwd: rustDir,
        stdio: 'inherit',
      });
      
      // Copy binary to bin directory
      const srcBinary = path.join(rustDir, 'target', 'release', process.platform === 'win32' ? 'vault.exe' : 'vault');
      fs.copyFileSync(srcBinary, binaryPath);
      
      console.log('vault-cli built and installed successfully!');
    }
  } catch (error) {
    console.error('Installation failed:', error.message);
    process.exit(1);
  }
}

// Run installation
install();