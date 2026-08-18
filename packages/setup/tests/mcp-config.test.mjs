import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const require = createRequire(import.meta.url);
const { mergeMcpServers } = require('../mcp-config.js');

function tmpFile(contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sk-mcp-'));
  const file = path.join(dir, '.mcp.json');
  if (contents !== undefined) fs.writeFileSync(file, contents);
  return file;
}

const SYSKNIFE = { sysknife: { command: '/bin/sysknife', args: ['mcp-server'] } };

test('merges sysknife in while preserving other servers', () => {
  const file = tmpFile(JSON.stringify({ mcpServers: { other: { command: 'x', args: [] } } }));
  const merged = mergeMcpServers(file, SYSKNIFE);
  assert.deepEqual(Object.keys(merged.mcpServers).sort(), ['other', 'sysknife']);
  assert.equal(merged.mcpServers.other.command, 'x'); // untouched
});

test('preserves unrelated top-level keys', () => {
  const file = tmpFile(JSON.stringify({ mcpServers: {}, editorConfig: 42 }));
  const merged = mergeMcpServers(file, SYSKNIFE);
  assert.equal(merged.editorConfig, 42);
});

test('creates a fresh config when the file is missing', () => {
  const file = tmpFile(); // not written
  const merged = mergeMcpServers(file, SYSKNIFE);
  assert.deepEqual(Object.keys(merged.mcpServers), ['sysknife']);
});

test('treats empty and whitespace-only configs as fresh configs', () => {
  for (const contents of ['', '  \r\n\t  ']) {
    const file = tmpFile(contents);
    const merged = mergeMcpServers(file, SYSKNIFE);
    assert.deepEqual(Object.keys(merged.mcpServers), ['sysknife']);
  }
});

test('accepts a UTF-8 BOM and preserves existing servers', () => {
  const file = tmpFile(
    `\ufeff${JSON.stringify({ mcpServers: { other: { command: 'x', args: [] } } })}`
  );
  const merged = mergeMcpServers(file, SYSKNIFE);
  assert.deepEqual(Object.keys(merged.mcpServers).sort(), ['other', 'sysknife']);
});

test('refuses to overwrite a malformed existing config', () => {
  const original = '{\n  "mcpServers": {"other": {"command": "x", "args": []}},\n}\n';
  const file = tmpFile(original);

  assert.throws(
    () => mergeMcpServers(file, SYSKNIFE),
    /malformed.*refusing to overwrite/i,
    'a malformed config must abort the merge instead of discarding other servers'
  );
  assert.equal(fs.readFileSync(file, 'utf8'), original);
});

test('refuses valid JSON that is not an object', () => {
  for (const original of ['[]', 'null', '"x"']) {
    const file = tmpFile(original);
    assert.throws(
      () => mergeMcpServers(file, SYSKNIFE),
      /must contain a JSON object.*refusing to overwrite/i
    );
    assert.equal(fs.readFileSync(file, 'utf8'), original);
  }
});

test('malformed-config errors keep location but do not echo source contents', () => {
  const file = tmpFile('{"mcpServers": {},}');
  let error;
  try {
    mergeMcpServers(file, SYSKNIFE);
  } catch (e) {
    error = e;
  }
  assert.ok(error instanceof Error);
  assert.match(error.message, /malformed JSON/i);
  assert.match(error.message, /position \d+/i);

  const markerFile = tmpFile('NO_ECHO_MARKER_12345');
  let markerError;
  try {
    mergeMcpServers(markerFile, SYSKNIFE);
  } catch (e) {
    markerError = e;
  }
  assert.ok(markerError instanceof Error);
  assert.doesNotMatch(markerError.message, /NO_ECHO_MARKER_12345/);
});

test('upserts a stale sysknife entry', () => {
  const file = tmpFile(JSON.stringify({ mcpServers: { sysknife: { command: 'OLD', args: [] } } }));
  const merged = mergeMcpServers(file, { sysknife: { command: 'NEW', args: ['mcp-server'] } });
  assert.equal(merged.mcpServers.sysknife.command, 'NEW');
});

test('handles a file with no mcpServers key', () => {
  const file = tmpFile(JSON.stringify({ somethingElse: true }));
  const merged = mergeMcpServers(file, SYSKNIFE);
  assert.equal(merged.somethingElse, true);
  assert.deepEqual(Object.keys(merged.mcpServers), ['sysknife']);
});

test('refuses to merge when the existing config cannot be read', () => {
  // A read failure is not malformed JSON. Silently starting from {} would make
  // the caller write a fresh file over the top, discarding every other MCP
  // server the user had configured.
  const file = tmpFile('{"mcpServers":{"other":{"command":"x"}}}');
  fs.chmodSync(file, 0o000);
  try {
    // Running as root defeats the permission check; skip rather than assert
    // something the environment cannot demonstrate.
    let readable = true;
    try {
      fs.readFileSync(file, 'utf8');
    } catch {
      readable = false;
    }
    if (readable) return;

    assert.throws(
      () => mergeMcpServers(file, SYSKNIFE),
      /refusing to overwrite/,
      'an unreadable config must abort the merge, not silently reset it'
    );
  } finally {
    fs.chmodSync(file, 0o600);
  }
});

test('malformed-config errors identify the file that was refused', () => {
  const file = tmpFile('{not valid json');

  assert.throws(
    () => mergeMcpServers(file, SYSKNIFE),
    (error) => error.message.includes(file) && /refusing to overwrite/i.test(error.message)
  );
});
