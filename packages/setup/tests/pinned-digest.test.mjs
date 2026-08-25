/**
 * pinned-digest.test.mjs
 *
 * The installer downloads the binaries and the `sha256sums` file from the same
 * GitHub release, then checks one against the other. That detects corruption and
 * a swapped asset, but it is not an independent authority: whoever can publish
 * the release can publish a malicious daemon together with a matching checksum,
 * and the daemon is designed to hold broad passwordless sudo.
 *
 * Release signing with a pinned publisher key is the real answer and needs key
 * custody decisions outside this package. What belongs here is the hook a
 * cautious operator can use today: pin the expected digest out of band (from a
 * signed tag, an internal mirror, a config-management value) and have the
 * installer refuse anything else.
 *
 * Also pinned: the verifier must report the digest it accepted, so the value can
 * be cross-checked at all rather than being verified invisibly.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { verifySha256, digestFor, pinnedDigestFor, pinLookup } = require('../install-binary.js');

const PAYLOAD = Buffer.from('#!/bin/sh\necho sysknife\n');
const DIGEST = crypto.createHash('sha256').update(PAYLOAD).digest('hex');
const SUMS = `${DIGEST}  sysknife-v9.9.9-linux-x86_64\n`;
const ASSET = 'sysknife-v9.9.9-linux-x86_64';

test('a matching release checksum returns the digest it verified', () => {
  const verified = verifySha256(PAYLOAD, SUMS, ASSET);
  assert.equal(
    verified,
    DIGEST,
    'the accepted digest must be returned so the caller can show it for cross-checking',
  );
});

test('a pinned digest that matches is accepted', () => {
  const verified = verifySha256(PAYLOAD, SUMS, ASSET, { pinnedSha256: DIGEST });
  assert.equal(verified, DIGEST);
});

test('a pinned digest is compared case-insensitively and ignores surrounding space', () => {
  const verified = verifySha256(PAYLOAD, SUMS, ASSET, {
    pinnedSha256: `  ${DIGEST.toUpperCase()}\n`,
  });
  assert.equal(verified, DIGEST);
});

test('a pinned digest that disagrees with the release is refused', () => {
  const wrong = 'a'.repeat(64);
  assert.throws(
    () => verifySha256(PAYLOAD, SUMS, ASSET, { pinnedSha256: wrong }),
    (e) => {
      assert.match(e.message, /pinned/i, `error must name the pin: ${e.message}`);
      assert.ok(
        e.message.includes(wrong) && e.message.includes(DIGEST),
        `error must show both digests so the operator can tell which is stale: ${e.message}`,
      );
      return true;
    },
    'a release whose digest differs from the operator-supplied pin must not install',
  );
});

test('a malformed pin is rejected rather than silently ignored', () => {
  // Silently ignoring an unusable pin would turn a deliberate security control
  // into a no-op — the worst possible outcome for this feature.
  for (const bad of ['not-a-digest', DIGEST.slice(0, 63), `${DIGEST}ff`]) {
    assert.throws(
      () => verifySha256(PAYLOAD, SUMS, ASSET, { pinnedSha256: bad }),
      /64 hex|not a valid/i,
      `malformed pin ${bad} must be an error`,
    );
  }
});

test('release-checksum mismatch still fails even with no pin', () => {
  assert.throws(
    () => verifySha256(Buffer.from('tampered'), SUMS, ASSET),
    /SHA256 mismatch/,
  );
});

// ---------------------------------------------------------------------------
// The pin must not go quiet when the sums file does not name the asset.
//
// Asset names carry the release tag, so they change on every version bump. An
// operator who pinned one release and then installs the next has a sums file
// that names nothing being downloaded. Skipping the gate there hands the
// publisher exactly the capability the pin exists to withhold, while the
// installer still prints that it is pinning.
// ---------------------------------------------------------------------------

const OLD_ASSET = 'sysknife-v0.8.0-linux-x86_64';
const NEW_ASSET = 'sysknife-v0.9.0-linux-x86_64';
const PINS_PATH = '/etc/sysknife/pins.txt';
const STALE_PINS = `${DIGEST}  ${OLD_ASSET}\n`;

test('digestFor still reports a missing entry as null', () => {
  // The lookup keeps its contract; the decision to refuse belongs to the caller
  // that knows a pin was requested.
  assert.equal(digestFor(STALE_PINS, NEW_ASSET), null);
  assert.equal(digestFor(STALE_PINS, OLD_ASSET), DIGEST);
});

test('a pinned sums file that does not name the asset refuses the install', () => {
  assert.throws(
    () => pinnedDigestFor(STALE_PINS, NEW_ASSET, PINS_PATH),
    (e) => {
      assert.ok(
        e.message.includes(NEW_ASSET),
        `error must name the asset that went unpinned: ${e.message}`,
      );
      assert.ok(
        e.message.includes(PINS_PATH),
        `error must name the file that was supposed to pin it: ${e.message}`,
      );
      return true;
    },
    'an asset the pinned file does not mention must not install unpinned',
  );
});

test('a pinned sums file that names the asset returns its digest', () => {
  assert.equal(pinnedDigestFor(STALE_PINS, OLD_ASSET, PINS_PATH), DIGEST);
});

test('a null pin reaching verifySha256 is fatal, not treated as no pin', () => {
  // Defence in depth: whatever the caller does, `null` must never mean "unpinned".
  assert.throws(
    () => verifySha256(PAYLOAD, SUMS, ASSET, { pinnedSha256: null }),
    /not a valid digest/i,
    'null must take the unusable-pin path, not the no-pin path',
  );
});

test('an absent pin option still means no pin', () => {
  assert.equal(verifySha256(PAYLOAD, SUMS, ASSET), DIGEST);
  assert.equal(verifySha256(PAYLOAD, SUMS, ASSET, {}), DIGEST);
  assert.equal(verifySha256(PAYLOAD, SUMS, ASSET, { pinnedSha256: undefined }), DIGEST);
});

// ---------------------------------------------------------------------------
// The wiring, not just the lookup.
//
// Every test above calls `pinnedDigestFor` directly, so all of them pass with
// the download path still asking `digestFor` — the exact line this change
// fixes. These pin what the installer builds and hands to the gate.
// ---------------------------------------------------------------------------

test('the lookup the installer builds refuses an asset a loaded pin file does not name', () => {
  const pinFor = pinLookup(STALE_PINS, PINS_PATH);
  assert.throws(
    () => pinFor(NEW_ASSET),
    (e) => {
      assert.ok(
        e.message.includes(NEW_ASSET) && e.message.includes(PINS_PATH),
        `error must name the asset and the pin file: ${e.message}`,
      );
      return true;
    },
    'a lookup built over a stale pin file must refuse, not return null',
  );
});

test('the lookup returns the pinned digest for an asset the file does name', () => {
  assert.equal(pinLookup(STALE_PINS, PINS_PATH)(OLD_ASSET), DIGEST);
});

test('with no pin file loaded the lookup yields undefined, the only unpinned value', () => {
  // Not null: verifySha256 takes null down the unusable-pin path on purpose,
  // so a lookup returning it would refuse every unpinned install.
  for (const empty of [null, '', undefined]) {
    const pinFor = pinLookup(empty, undefined);
    assert.equal(pinFor(ASSET), undefined);
    assert.equal(
      verifySha256(PAYLOAD, SUMS, ASSET, { pinnedSha256: pinFor(ASSET) }),
      DIGEST,
      'an install with no pin file must still verify against the release sums',
    );
  }
});

test('the value the lookup produces is what the gate enforces', () => {
  // The end-to-end shape of the defect: a pin file naming a different release
  // must stop the install at verifySha256, through the lookup rather than
  // around it.
  const pinFor = pinLookup(STALE_PINS, PINS_PATH);
  assert.throws(
    () => verifySha256(PAYLOAD, SUMS, NEW_ASSET, { pinnedSha256: pinFor(NEW_ASSET) }),
    (e) => {
      assert.ok(
        e.message.includes(NEW_ASSET) && e.message.includes(PINS_PATH),
        `the refusal must come from the pin lookup, naming both: ${e.message}`,
      );
      return true;
    },
  );
});
