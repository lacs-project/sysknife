#!/usr/bin/env node
'use strict';

/**
 * install-binary.js — prebuilt SysKnife binary installer
 *
 * Contract:
 *   installBinaryIfMissing(opts) → Promise<{ installed: boolean, path: string }>
 *
 *   opts.ask(question, defaultVal)  — async prompt helper from index.js
 *   opts.noPrompts                  — boolean; accept all defaults silently
 *   opts.noBinary                   — boolean; skip download entirely
 *
 * This module uses only Node built-ins: https, crypto, fs/promises, path, os,
 * child_process.  No new npm dependencies are added.
 *
 * Security: every downloaded binary is SHA256-verified against the companion
 * sha256sums-linux-<arch>.txt before it is written to disk.  A mismatch is a
 * hard error — the partial file is deleted and the function throws.
 */

const https        = require('node:https');
const crypto       = require('node:crypto');
const fsp          = require('node:fs/promises');
const fs           = require('node:fs');
const path         = require('node:path');
const os           = require('node:os');
const { execFileSync } = require('node:child_process');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** GitHub API endpoint for the latest sysknife release. */
const RELEASES_API = 'https://api.github.com/repos/lacs-project/sysknife/releases/latest';

/** User-agent required by GitHub API. */
const USER_AGENT = 'sysknife-setup/0.1 (node)';

/**
 * Default install path when XDG_BIN_HOME is not set and ~/.local/bin is not
 * on PATH.  We prefer ~/.local/bin over /usr/local/bin so that the common
 * case requires no sudo.
 */
const DEFAULT_LOCAL_BIN = path.join(os.homedir(), '.local', 'bin');

// ---------------------------------------------------------------------------
// Terminal helpers (mirror the ones in index.js — no shared module dep)
// ---------------------------------------------------------------------------

const ESC = '\x1b[';
const G = `${ESC}32m`;
const Y = `${ESC}33m`;
const R = `${ESC}31m`;
const B = `${ESC}1m`;
const D = `${ESC}2m`;
const X = `${ESC}0m`;

function ok(msg)   { console.log(`  ${G}✓${X}  ${msg}`); }
function warn(msg) { console.log(`  ${Y}⚠${X}  ${msg}`); }
function step(msg) { console.log(`  ${D}→${X}  ${msg}`); }
function err(msg)  { console.log(`  ${R}✗${X}  ${msg}`); }

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

/**
 * Detect host arch and map Node's names to GitHub release asset suffixes.
 * Throws a descriptive error for unsupported platforms so the wizard fails
 * early rather than silently writing nothing.
 *
 * @returns {{ arch: string, os: string }} e.g. { arch: 'x86_64', os: 'linux' }
 */
function detectPlatform() {
  if (process.platform !== 'linux') {
    throw new Error(
      `SysKnife is Linux-only; see https://github.com/lacs-project/sysknife for cross-distro plans.\n` +
      `  Detected platform: ${process.platform}`
    );
  }

  const archMap = { x64: 'x86_64', arm64: 'aarch64' };
  const arch = archMap[process.arch];
  if (!arch) {
    throw new Error(
      `Unsupported architecture: ${process.arch}. ` +
      `SysKnife ships prebuilts for x86_64 and aarch64 only.`
    );
  }

  return { arch, os: 'linux' };
}

// ---------------------------------------------------------------------------
// PATH helpers
// ---------------------------------------------------------------------------

/** Return true if `dir` appears anywhere in PATH. */
function isOnPath(dir) {
  const pathDirs = (process.env.PATH || '').split(':').map(p => p.replace(/\/$/, ''));
  return pathDirs.includes(dir.replace(/\/$/, ''));
}

/**
 * Emit shell-specific advice for adding a directory to PATH.
 * Detects shell from SHELL env or falls back to bash.
 */
function printAddToPathAdvice(dir) {
  const shell = path.basename(process.env.SHELL || 'bash');
  console.log();
  warn(`${dir} is not on your PATH.`);
  if (shell === 'fish') {
    step(`fish: fish_add_path ${dir}`);
  } else if (shell === 'zsh') {
    step(`zsh:  echo 'export PATH="${dir}:$PATH"' >> ~/.zshrc && source ~/.zshrc`);
  } else {
    step(`bash: echo 'export PATH="${dir}:$PATH"' >> ~/.bashrc && source ~/.bashrc`);
  }
}

// ---------------------------------------------------------------------------
// Choose install directory
// ---------------------------------------------------------------------------

/**
 * Ask the user where to install the binaries.
 *
 * Priority:
 *   1. XDG_BIN_HOME if set
 *   2. ~/.local/bin if writable (no sudo, preferred)
 *   3. /usr/local/bin (sudo required)
 *
 * @param {Function} ask      - async prompt function
 * @param {boolean}  noPrompts
 * @returns {Promise<string>} absolute directory path
 */
async function chooseInstallDir(ask, noPrompts) {
  // XDG_BIN_HOME takes precedence when set.
  if (process.env.XDG_BIN_HOME) {
    const xdg = process.env.XDG_BIN_HOME;
    step(`Using XDG_BIN_HOME: ${xdg}`);
    return xdg;
  }

  const localBin = DEFAULT_LOCAL_BIN;
  let localWritable = false;
  try {
    await fsp.mkdir(localBin, { recursive: true });
    await fsp.access(localBin, fs.constants.W_OK);
    localWritable = true;
  } catch {
    localWritable = false;
  }

  const defaultDir = localWritable ? localBin : '/usr/local/bin';

  if (noPrompts) {
    return defaultDir;
  }

  console.log();
  console.log(`  ${B}Binary install location${X}`);
  console.log(`    1) ${localBin}  ${D}(no sudo, default when writable)${X}`);
  console.log(`    2) /usr/local/bin  ${D}(sudo required)${X}`);
  console.log();

  const answer = await ask('Install location (1 / 2 or full path)', defaultDir === localBin ? '1' : '2');
  if (answer === '1') return localBin;
  if (answer === '2') return '/usr/local/bin';
  // Allow user to type a custom path
  return answer.startsWith('~') ? answer.replace('~', os.homedir()) : answer;
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/**
 * Perform an HTTPS GET and return the full response body as a Buffer.
 * Follows up to 5 redirects.  Rejects on HTTP errors.
 *
 * @param {string} url
 * @param {number} [redirectsLeft=5]
 * @returns {Promise<Buffer>}
 */
function fetchBuffer(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'application/octet-stream',
      },
    }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) {
        if (redirectsLeft <= 0) { reject(new Error('Too many redirects')); return; }
        req.destroy();
        resolve(fetchBuffer(res.headers.location, redirectsLeft - 1));
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
        return;
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end',  () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('error', reject);
  });
}

/**
 * Perform an HTTPS GET with progress reporting.
 * Prints a CR-overwritten progress line: [ 12.3 MB / 23.5 MB ]
 *
 * @param {string} url
 * @param {string} label  - short label shown in the progress line
 * @returns {Promise<Buffer>}
 */
function fetchWithProgress(url, label, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'application/octet-stream',
      },
    }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) {
        if (redirectsLeft <= 0) { reject(new Error('Too many redirects')); return; }
        req.destroy();
        resolve(fetchWithProgress(res.headers.location, label, redirectsLeft - 1));
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
        return;
      }

      const total = parseInt(res.headers['content-length'] || '0', 10);
      const chunks = [];
      let received = 0;

      res.on('data', (chunk) => {
        chunks.push(chunk);
        received += chunk.length;
        const recMb  = (received / 1_048_576).toFixed(1);
        const totMb  = total ? (total / 1_048_576).toFixed(1) : '?';
        process.stdout.write(`\r  ${D}↓${X}  ${label}: [ ${recMb} MB / ${totMb} MB ]`);
      });

      res.on('end', () => {
        process.stdout.write('\n');
        resolve(Buffer.concat(chunks));
      });

      res.on('error', reject);
    });
    req.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// GitHub release helpers
// ---------------------------------------------------------------------------

/**
 * Fetch release metadata from the GitHub Releases API.
 * Returns parsed JSON or throws on network / parse error.
 *
 * @param {string} [url] override for testing
 * @returns {Promise<object>}
 */
async function fetchLatestRelease(url = RELEASES_API) {
  const buf = await fetchBuffer(url);
  return JSON.parse(buf.toString('utf8'));
}

/**
 * Pick the download URL for a named asset from a release.
 *
 * @param {object} release  - parsed GitHub release object
 * @param {string} name     - exact asset filename
 * @returns {string | null}
 */
function assetUrl(release, name) {
  const asset = (release.assets || []).find(a => a.name === name);
  return asset ? asset.browser_download_url : null;
}

// ---------------------------------------------------------------------------
// SHA256 verification
// ---------------------------------------------------------------------------

/**
 * Verify `data` against an entry in a sha256sums file.
 * The sums file format is:  <hex>  <filename>
 *
 * Throws if the filename is not found in the sums file or if the hash
 * does not match (fails-closed: a missing entry is treated as a failure).
 *
 * @param {Buffer} data        - file content to verify
 * @param {string} sumsText    - full text of the sha256sums file
 * @param {string} filename    - asset filename to look up
 */
function verifySha256(data, sumsText, filename) {
  const lines = sumsText
    .split('\n')
    .map(l => l.replace(/\r$/, '')) // tolerate CRLF-terminated sums files
    .filter(l => l.trim());
  const entry = lines.find(l => l.endsWith(`  ${filename}`) || l.endsWith(`\t${filename}`));
  if (!entry) {
    throw new Error(
      `SHA256 verification failed: "${filename}" not found in sha256sums file. ` +
      `Refusing to install unverified binary.`
    );
  }
  const expected = entry.split(/\s+/)[0].toLowerCase();
  const actual   = crypto.createHash('sha256').update(data).digest('hex').toLowerCase();
  if (actual !== expected) {
    throw new Error(
      `SHA256 mismatch for ${filename}!\n` +
      `  Expected: ${expected}\n` +
      `  Got:      ${actual}\n` +
      `Refusing to install — binary may be corrupted or tampered with.`
    );
  }
}

// ---------------------------------------------------------------------------
// Write binary to disk
// ---------------------------------------------------------------------------

/**
 * Write `data` to `destPath` as an executable file (mode 0o755).
 * Creates the destination directory if needed.
 * If `destPath` is under /usr/local/bin or another root-owned directory,
 * falls back to writing via `sudo install -o root -g root -m 755`.
 *
 * @param {Buffer} data
 * @param {string} destPath  absolute path
 */
async function writeBinary(data, destPath) {
  const dir = path.dirname(destPath);

  try {
    await fsp.mkdir(dir, { recursive: true });
    await fsp.writeFile(destPath, data, { mode: 0o755 });
  } catch (e) {
    if (e.code === 'EACCES' || e.code === 'EPERM') {
      // Attempt sudo tee fallback
      step(`Writing to ${destPath} requires elevated privileges — sudo may prompt.`);
      const tmp = path.join(os.tmpdir(), `sysknife-install-${process.pid}-${path.basename(destPath)}`);
      await fsp.writeFile(tmp, data, { mode: 0o644 });
      execFileSync('sudo', ['install', '-o', 'root', '-g', 'root', '-m', '755', tmp, destPath], {
        stdio: 'inherit',
      });
      await fsp.rm(tmp, { force: true });
    } else {
      throw e;
    }
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Main entry point called by index.js.
 *
 * Detects whether sysknife is already installed, asks the user whether to
 * reuse or reinstall, and downloads + verifies + installs prebuilts when
 * needed.
 *
 * @param {{ ask: Function, noPrompts: boolean, noBinary: boolean }} opts
 * @returns {Promise<{ installed: boolean, path: string }>}
 *   installed — true if a binary was freshly installed
 *   path      — absolute path to the sysknife binary (existing or new)
 */
async function installBinaryIfMissing(opts) {
  const { ask, noPrompts = false, noBinary = false } = opts;

  // --no-binary skips the whole flow; caller provides the binary path manually.
  if (noBinary) {
    step('--no-binary: skipping prebuilt download. Build from source and set the path manually.');
    return { installed: false, path: '/usr/local/bin/sysknife' };
  }

  // Platform gate — bail early on non-Linux / unsupported arch.
  let platform;
  try {
    platform = detectPlatform();
  } catch (e) {
    err(e.message);
    process.exit(1);
  }

  const { arch } = platform;

  // --- Probe for existing binary ---
  let existingPath = null;
  try {
    existingPath = execFileSync('which', ['sysknife'], { stdio: ['pipe', 'pipe', 'pipe'] })
      .toString().trim();
  } catch {
    // not in PATH — that's fine, we'll install it
  }

  if (existingPath) {
    ok(`Found existing sysknife at ${existingPath}`);
    if (noPrompts) {
      step('Using existing binary (--no-prompts).');
      return { installed: false, path: existingPath };
    }
    const ans = await ask(`Use existing ${existingPath}?`, 'Y');
    if (ans.toLowerCase().startsWith('y') || ans === '') {
      return { installed: false, path: existingPath };
    }
    // User chose to reinstall — fall through to download.
  }

  // --- Idempotence: check default install paths even if not on PATH ---
  const xdgBin = process.env.XDG_BIN_HOME;
  const candidatePaths = [
    xdgBin ? path.join(xdgBin, 'sysknife') : null,
    path.join(DEFAULT_LOCAL_BIN, 'sysknife'),
    '/usr/local/bin/sysknife',
  ].filter(Boolean);

  for (const candidate of candidatePaths) {
    try {
      await fsp.access(candidate, fs.constants.X_OK);
      ok(`Found sysknife at ${candidate} (not on PATH)`);
      if (!noPrompts) {
        const ans = await ask(`Reinstall?`, 'N');
        if (!ans.toLowerCase().startsWith('y')) {
          return { installed: false, path: candidate };
        }
      } else {
        return { installed: false, path: candidate };
      }
    } catch {
      // not there
    }
  }

  // --- Fetch latest release metadata ---
  step('Fetching latest release from GitHub…');
  let release;
  try {
    release = await fetchLatestRelease();
  } catch (e) {
    err(`Failed to fetch release metadata: ${e.message}`);
    err('Check your internet connection or install manually:');
    step('https://github.com/lacs-project/sysknife/releases/latest');
    process.exit(1);
  }

  const version = release.tag_name || 'unknown';
  ok(`Latest release: ${version}`);

  // Asset names follow: sysknife-vX.Y.Z-linux-<arch>
  const cliAsset     = `sysknife-${version}-linux-${arch}`;
  const daemonAsset  = `sysknife-daemon-${version}-linux-${arch}`;
  const sumsAsset    = `sha256sums-linux-${arch}.txt`;

  const cliUrl     = assetUrl(release, cliAsset);
  const daemonUrl  = assetUrl(release, daemonAsset);
  const sumsUrl    = assetUrl(release, sumsAsset);

  if (!cliUrl || !daemonUrl || !sumsUrl) {
    err(`Could not find expected release assets for linux-${arch}.`);
    err(`Assets expected:`);
    step(cliAsset);
    step(daemonAsset);
    step(sumsAsset);
    err('Install manually from: https://github.com/lacs-project/sysknife/releases/latest');
    process.exit(1);
  }

  // --- Choose install directory ---
  const installDir = await chooseInstallDir(ask, noPrompts);

  // --- Download sha256sums first (small — no progress needed) ---
  step(`Downloading ${sumsAsset}…`);
  let sumsData;
  try {
    sumsData = await fetchBuffer(sumsUrl);
  } catch (e) {
    err(`Failed to download sha256sums: ${e.message}`);
    process.exit(1);
  }
  const sumsText = sumsData.toString('utf8');

  // --- Download and verify sysknife CLI ---
  console.log();
  let cliBuf;
  try {
    cliBuf = await fetchWithProgress(cliUrl, cliAsset);
  } catch (e) {
    err(`Failed to download ${cliAsset}: ${e.message}`);
    process.exit(1);
  }

  try {
    verifySha256(cliBuf, sumsText, cliAsset);
    ok(`SHA256 verified: ${cliAsset}`);
  } catch (e) {
    err(e.message);
    process.exit(1);
  }

  // --- Download and verify sysknife-daemon ---
  let daemonBuf;
  try {
    daemonBuf = await fetchWithProgress(daemonUrl, daemonAsset);
  } catch (e) {
    err(`Failed to download ${daemonAsset}: ${e.message}`);
    process.exit(1);
  }

  try {
    verifySha256(daemonBuf, sumsText, daemonAsset);
    ok(`SHA256 verified: ${daemonAsset}`);
  } catch (e) {
    err(e.message);
    process.exit(1);
  }

  // --- Write to disk ---
  const cliDest    = path.join(installDir, 'sysknife');
  const daemonDest = path.join(installDir, 'sysknife-daemon');

  try {
    await writeBinary(cliBuf,    cliDest);
    ok(`Installed ${cliDest}`);
    await writeBinary(daemonBuf, daemonDest);
    ok(`Installed ${daemonDest}`);
  } catch (e) {
    err(`Install failed: ${e.message}`);
    process.exit(1);
  }

  if (!isOnPath(installDir)) {
    printAddToPathAdvice(installDir);
  }

  return { installed: true, path: cliDest };
}

module.exports = { installBinaryIfMissing, detectPlatform, verifySha256, isOnPath };
