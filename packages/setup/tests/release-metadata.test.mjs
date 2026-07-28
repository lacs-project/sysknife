/**
 * release-metadata.test.mjs
 *
 * The GitHub releases *metadata* endpoint rejects `Accept:
 * application/octet-stream` with HTTP 415 — that media type is only correct for
 * asset downloads. Sending it on the metadata request broke every
 * `npx sysknife-setup` run:
 *
 *   ✗  Failed to fetch release metadata: HTTP 415 fetching
 *      https://api.github.com/repos/lacs-project/sysknife/releases/latest
 *
 * Verified against the live API: `application/vnd.github+json` → 200,
 * `application/octet-stream` → 415. These tests pin the two Accept values to
 * the two kinds of request so the asset header can never leak back onto the
 * metadata call.
 *
 * Offline — the fetcher is injected, no real network call is made.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fsp from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const {
  fetchLatestRelease,
  GITHUB_JSON_ACCEPT,
  ASSET_ACCEPT,
} = require('../install-binary.js');

test('the metadata request asks for GitHub JSON, not octet-stream', async () => {
  const seen = [];
  const fixture = await fsp.readFile(
    path.join(__dirname, 'fixtures', 'fake-release.json'),
    'utf8',
  );
  const fakeFetch = (url, opts) => {
    seen.push({ url, accept: opts && opts.accept });
    return Promise.resolve(Buffer.from(fixture));
  };

  const release = await fetchLatestRelease('https://example.invalid/releases/latest', fakeFetch);

  assert.equal(seen.length, 1);
  assert.equal(
    seen[0].accept,
    'application/vnd.github+json',
    'metadata must be requested as GitHub JSON; application/octet-stream returns HTTP 415',
  );
  assert.ok(Array.isArray(release.assets), 'the response is parsed as a release object');
});

test('the two Accept values stay distinct and correctly valued', () => {
  assert.equal(GITHUB_JSON_ACCEPT, 'application/vnd.github+json');
  assert.equal(ASSET_ACCEPT, 'application/octet-stream');
  assert.notEqual(GITHUB_JSON_ACCEPT, ASSET_ACCEPT);
});
