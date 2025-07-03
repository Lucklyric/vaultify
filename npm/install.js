#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const https = require('https');
const tar = require('tar');

const REPO = 'Lucklyric/vaultify';
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
  // Match the naming in our GitHub release workflow
  if (process.platform === 'linux' && process.arch === 'x64') {
    return 'vaultify-linux-x64';
  } else if (process.platform === 'darwin' && process.arch === 'x64') {
    return 'vaultify-macos-x64';
  } else if (process.platform === 'darwin' && process.arch === 'arm64') {
    return 'vaultify-macos-arm64';
  } else if (process.platform === 'win32' && process.arch === 'x64') {
    return 'vaultify-windows-x64';
  }
  throw new Error(`Unsupported platform: ${process.platform} ${process.arch}`);
}

function getBinaryUrl() {
  const binaryName = getBinaryName();
  const ext = process.platform === 'win32' ? '.zip' : '.tar.gz';
  return `https://github.com/${REPO}/releases/download/v${VERSION}/${binaryName}${ext}`;
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

async function extractBinary(archivePath, destDir) {
  console.log('Extracting binary...');
  
  if (process.platform === 'win32') {
    // For Windows, we need to extract zip files
    const AdmZip = require('adm-zip');
    const zip = new AdmZip(archivePath);
    zip.extractAllTo(destDir, true);
  } else {
    // For Unix systems, extract tar.gz
    await tar.extract({
      file: archivePath,
      cwd: destDir,
    });
  }
}

async function install() {
  try {
    const binDir = path.join(__dirname, 'bin');
    
    // Create bin directory
    if (!fs.existsSync(binDir)) {
      fs.mkdirSync(binDir, { recursive: true });
    }
    
    // Check if binary already exists
    const binaryName = process.platform === 'win32' ? 'vaultify.exe' : 'vaultify';
    const binaryPath = path.join(binDir, binaryName);
    if (fs.existsSync(binaryPath)) {
      console.log('Binary already installed.');
      return;
    }
    
    // Download binary
    const url = getBinaryUrl();
    const ext = process.platform === 'win32' ? '.zip' : '.tar.gz';
    const archivePath = path.join(binDir, `vaultify${ext}`);
    
    try {
      await downloadBinary(url, archivePath);
      await extractBinary(archivePath, binDir);
      
      // Clean up archive file
      fs.unlinkSync(archivePath);
      
      // Rename extracted binary if needed
      if (process.platform !== 'win32') {
        const extractedPath = path.join(binDir, 'vaultify');
        if (fs.existsSync(extractedPath) && extractedPath !== binaryPath) {
          fs.renameSync(extractedPath, binaryPath);
        }
      }
      
      // Make binary executable on Unix
      if (process.platform !== 'win32') {
        fs.chmodSync(binaryPath, 0o755);
      }
      
      console.log('vaultify installed successfully!');
    } catch (error) {
      // Fallback: try to build from source
      console.error('Failed to download pre-built binary:', error.message);
      console.error('\nPossible reasons:');
      console.error('1. The release is still being built. Please try again in a few minutes.');
      console.error('2. Your platform/architecture may not be supported.');
      console.error('\nYou can:');
      console.error('1. Wait a few minutes and try reinstalling');
      console.error('2. Check https://github.com/Lucklyric/vaultify/releases for available binaries');
      console.error('3. Build from source by cloning the repository');
      
      throw new Error('Binary download failed. See above for solutions.');
    }
  } catch (error) {
    console.error('Installation failed:', error.message);
    process.exit(1);
  }
}

// Run installation
install();