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

test('does not throw on a malformed file (starts fresh)', () => {
  const file = tmpFile('{ not: valid json ');
  const merged = mergeMcpServers(file, SYSKNIFE);
  assert.deepEqual(Object.keys(merged.mcpServers), ['sysknife']);
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
