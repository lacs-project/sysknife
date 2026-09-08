import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const installerPath = fileURLToPath(new URL('../install-binary.js', import.meta.url));
const source = fs.readFileSync(installerPath, 'utf8');

async function download({ chunks, total, isTTY = false, intervalMs = 10 }) {
  let output = '';
  let now = 0;
  const response = new EventEmitter();
  response.statusCode = 200;
  response.headers = total === undefined ? {} : { 'content-length': String(total) };
  const fakeHttps = {
    get(url, options, onResponse) {
      assert.equal(url, 'https://example.invalid/asset');
      assert.equal(options.headers.Accept, 'application/octet-stream');
      queueMicrotask(() => {
        onResponse(response);
        for (const chunk of chunks) {
          now += intervalMs;
          response.emit('data', chunk);
        }
        response.emit('end');
      });
      return new EventEmitter();
    },
  };

  // Exercise the private production downloader without exporting a test-only
  // API or contacting a server. The source is unchanged; only HTTPS, stdout
  // and the clock are substituted in its module context.
  const fetchWithProgress = vm.runInNewContext(`${source}\nfetchWithProgress;`, {
    require: id => id === 'node:https' ? fakeHttps : require(id),
    module: { exports: {} },
    Buffer,
    process: { stdout: { isTTY, write: text => { output += text; } } },
    Date: class extends Date { static now() { return now; } },
  }, { filename: installerPath });

  const bytes = await fetchWithProgress('https://example.invalid/asset', 'fixture');
  assert.deepEqual(bytes, Buffer.concat(chunks), 'progress must not change downloaded bytes');
  return output.replace(/\x1b\[[0-9;]*m/g, '');
}

for (const knownTotal of [true, false]) {
  test(`non-TTY progress is periodic and line-oriented with ${knownTotal ? 'known' : 'unknown'} size`, async () => {
    const chunks = Array.from({ length: 400 }, () => Buffer.alloc(4096, 0x61));
    const total = chunks.length * chunks[0].length;
    const output = await download({ chunks, total: knownTotal ? total : undefined });
    assert.doesNotMatch(output, /\r/, 'a captured log must not rely on terminal overwrites');
    assert.ok(output.endsWith('\n'));
    const lines = output.trimEnd().split('\n');
    assert.ok(lines.length >= 3, 'a longer download should report progress before completion');
    assert.ok(lines.length <= 6, `400 chunks over four seconds produced ${lines.length} lines`);
    const totalText = knownTotal ? '1.6' : '?';
    assert.ok(lines.every(line => line.includes(` MB / ${totalText} MB ]`)));
    assert.ok(lines.at(-1).endsWith(`[ 1.6 MB / ${totalText} MB ]`), 'report the final byte count');
  });
}

test('a fast non-TTY download reports its final count without one row per chunk', async () => {
  const chunks = Array.from({ length: 400 }, () => Buffer.alloc(4096, 0x62));
  const output = await download({ chunks, intervalMs: 0 });
  assert.doesNotMatch(output, /\r/);
  assert.ok(output.trimEnd().split('\n').length <= 2);
  assert.ok(output.endsWith('[ 1.6 MB / ? MB ]\n'));
});

test('empty and single-chunk non-TTY downloads still produce a final progress row', async () => {
  for (const chunks of [[], [Buffer.alloc(1_048_576, 0x63)]]) {
    const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const output = await download({ chunks, total });
    assert.doesNotMatch(output, /\r/);
    const received = (total / 1_048_576).toFixed(1);
    const expectedTotal = total ? received : '?';
    assert.ok(output.endsWith(`[ ${received} MB / ${expectedTotal} MB ]\n`));
  }
});

test('TTY progress keeps overwriting the same line and terminates it once', async () => {
  const output = await download({
    chunks: [Buffer.alloc(1_048_576), Buffer.alloc(1_048_576)],
    total: 2_097_152,
    isTTY: true,
  });
  assert.equal(output,
    '\r  ↓  fixture: [ 1.0 MB / 2.0 MB ]'
    + '\r  ↓  fixture: [ 2.0 MB / 2.0 MB ]\n');
});
