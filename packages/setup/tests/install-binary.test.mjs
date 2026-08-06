/**
 * install-binary.test.mjs
 *
 * Unit tests for install-binary.js using the Node built-in test runner.
 * Run with: node --test packages/setup/tests/install-binary.test.mjs
 *
 * All tests are offline — no real network calls are made.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import fsp from 'node:fs/promises';
import os from 'node:os';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// Import the module under test via CJS require (it's a CJS module).
const {
  verifySha256,
  detectPlatform,
  isOnPath,
  stageForPrivilegedInstall,
} = require('../install-binary.js');

// ---------------------------------------------------------------------------
// stageForPrivilegedInstall — the payload `sudo install` copies from
// ---------------------------------------------------------------------------

// `sudo install` copies these bytes to /usr/local/bin as root, mode 0755, so
// whatever sits at the staging path when the copy runs becomes the sysknife
// binary. The old path was `${os.tmpdir()}/sysknife-install-${process.pid}-...`
// at mode 0644: a predictable name in a world-writable directory. Any local user
// could pre-create it, let the installer write through it, then overwrite the
// contents before the sudo — a root trojan for anyone who can guess a pid.
test('privileged install staging is unguessable and private', async () => {
  const a = await stageForPrivilegedInstall(Buffer.from('payload-a'));
  const b = await stageForPrivilegedInstall(Buffer.from('payload-b'));
  try {
    // Same process, so same pid: a pid-derived name would collide here.
    assert.notEqual(a.dir, b.dir, 'staging directory must not be predictable');

    const dirMode = (await fsp.stat(a.dir)).mode & 0o777;
    assert.equal(
      dirMode, 0o700,
      `staging dir must be 0700 so no other user can enter it, got 0${dirMode.toString(8)}`
    );

    const fileMode = (await fsp.stat(a.file)).mode & 0o777;
    assert.equal(
      fileMode, 0o600,
      `staged payload must be 0600, got 0${fileMode.toString(8)}`
    );

    assert.equal(a.file, path.join(a.dir, path.basename(a.file)),
      'the staged file must live inside its own staging dir, not beside it');
    assert.equal((await fsp.readFile(a.file)).toString(), 'payload-a');
  } finally {
    await fsp.rm(a.dir, { recursive: true, force: true });
    await fsp.rm(b.dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// verifySha256 tests
// ---------------------------------------------------------------------------

test('verifySha256 accepts correct hash', () => {
  const data   = Buffer.from('hello sysknife\n');
  const hex    = crypto.createHash('sha256').update(data).digest('hex');
  const sums   = `${hex}  sysknife-v0.2.4-linux-x86_64\n`;
  // Must not throw
  assert.doesNotThrow(() => verifySha256(data, sums, 'sysknife-v0.2.4-linux-x86_64'));
});

test('verifySha256 rejects wrong hash', () => {
  const data   = Buffer.from('hello sysknife\n');
  const sums   = `${'00'.repeat(32)}  sysknife-v0.2.4-linux-x86_64\n`;
  assert.throws(
    () => verifySha256(data, sums, 'sysknife-v0.2.4-linux-x86_64'),
    /SHA256 mismatch/
  );
});

test('verifySha256 fails-closed on missing filename', () => {
  const data   = Buffer.from('hello\n');
  const sums   = `${'aa'.repeat(32)}  other-file.tar.gz\n`;
  assert.throws(
    () => verifySha256(data, sums, 'sysknife-v0.2.4-linux-x86_64'),
    /not found in sha256sums/
  );
});

test('verifySha256 is case-insensitive on hex', () => {
  const data   = Buffer.from('case test');
  const hex    = crypto.createHash('sha256').update(data).digest('hex').toUpperCase();
  const sums   = `${hex}  mybin\n`;
  assert.doesNotThrow(() => verifySha256(data, sums, 'mybin'));
});

test('verifySha256 tolerates a CRLF-terminated sums file', () => {
  const data = Buffer.from('crlf sums test');
  const hex  = crypto.createHash('sha256').update(data).digest('hex');
  // Windows-style line endings: every line ends with \r\n, not just \n.
  const sums = `${hex}  sysknife-v0.2.4-linux-x86_64\r\n`;
  assert.doesNotThrow(() => verifySha256(data, sums, 'sysknife-v0.2.4-linux-x86_64'));
});

// ---------------------------------------------------------------------------
// detectPlatform tests
// ---------------------------------------------------------------------------

test('detectPlatform returns arch/os on linux x64/arm64', () => {
  // We're running on linux; just assert the shape is correct.
  if (process.platform !== 'linux') {
    // On non-linux the function throws — that's the correct behaviour tested elsewhere.
    return;
  }
  const p = detectPlatform();
  assert.ok(p.arch === 'x86_64' || p.arch === 'aarch64', `unexpected arch: ${p.arch}`);
  assert.equal(p.os, 'linux');
});

// ---------------------------------------------------------------------------
// isOnPath tests
// ---------------------------------------------------------------------------

test('isOnPath returns true for a dir that is on PATH', async () => {
  // /usr/bin is almost certainly on PATH on any Linux machine running tests
  assert.equal(isOnPath('/usr/bin'), true);
});

test('isOnPath returns false for an arbitrary tmp directory', async () => {
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sk-test-'));
  assert.equal(isOnPath(tmpDir), false);
  await fsp.rm(tmpDir, { recursive: true });
});

// ---------------------------------------------------------------------------
// Fixture sanity — fake-release.json is parseable and has expected assets
// ---------------------------------------------------------------------------

test('fake-release.json fixture has expected asset names', async () => {
  const fixturesDir = path.join(__dirname, 'fixtures');
  const release = JSON.parse(
    await fsp.readFile(path.join(fixturesDir, 'fake-release.json'), 'utf8')
  );

  const names = release.assets.map(a => a.name);
  assert.ok(names.includes('sysknife-v0.2.4-linux-x86_64'));
  assert.ok(names.includes('sysknife-daemon-v0.2.4-linux-x86_64'));
  assert.ok(names.includes('sha256sums-linux-x86_64.txt'));
});

// ---------------------------------------------------------------------------
// Full mock-install integration test
// ---------------------------------------------------------------------------

test('full mock install: download → verify → write binary', async () => {
  // Build a tiny "binary" and its sha256sums.
  const fakeCliContent    = Buffer.from('#!/bin/sh\necho sysknife mock\n');
  const fakeDaemonContent = Buffer.from('#!/bin/sh\necho sysknife-daemon mock\n');
  const arch              = 'x86_64';
  const version           = 'v0.2.4';
  const cliName           = `sysknife-${version}-linux-${arch}`;
  const daemonName        = `sysknife-daemon-${version}-linux-${arch}`;

  const cliHex    = crypto.createHash('sha256').update(fakeCliContent).digest('hex');
  const daemonHex = crypto.createHash('sha256').update(fakeDaemonContent).digest('hex');
  const sumsText  = `${cliHex}  ${cliName}\n${daemonHex}  ${daemonName}\n`;

  // Verify both (the core security path).
  assert.doesNotThrow(() => verifySha256(fakeCliContent,    sumsText, cliName));
  assert.doesNotThrow(() => verifySha256(fakeDaemonContent, sumsText, daemonName));

  // Write to a temp dir to simulate the install step.
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sk-install-'));
  try {
    const cliDest    = path.join(tmpDir, 'sysknife');
    const daemonDest = path.join(tmpDir, 'sysknife-daemon');

    await fsp.writeFile(cliDest,    fakeCliContent,    { mode: 0o755 });
    await fsp.writeFile(daemonDest, fakeDaemonContent, { mode: 0o755 });

    const cliStat    = await fsp.stat(cliDest);
    const daemonStat = await fsp.stat(daemonDest);

    // Verify executability bits (owner execute = 0o100)
    assert.ok((cliStat.mode    & 0o100) !== 0, 'sysknife should be executable');
    assert.ok((daemonStat.mode & 0o100) !== 0, 'sysknife-daemon should be executable');

    // Verify content round-trips
    const cliRead    = await fsp.readFile(cliDest);
    const daemonRead = await fsp.readFile(daemonDest);
    assert.ok(fakeCliContent.equals(cliRead),    'cli content mismatch');
    assert.ok(fakeDaemonContent.equals(daemonRead), 'daemon content mismatch');
  } finally {
    await fsp.rm(tmpDir, { recursive: true });
  }
});
