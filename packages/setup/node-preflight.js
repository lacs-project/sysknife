'use strict';

/**
 * node-preflight.js — "is this Node new enough to even parse the wizard?"
 *
 * IMPORTANT: this file must stay parseable by Node 12, because that is the Node
 * that Ubuntu 22.04 installs from apt and therefore the version most likely to
 * be running when the check matters. No optional chaining, no nullish
 * coalescing, no logical assignment. tests/node-preflight.test.mjs enforces it.
 *
 * Why a separate file at all: `index.js` uses modern syntax, so on Node 12 it
 * raises `SyntaxError` at parse time — before any statement in it could run. A
 * guard written inside index.js could never execute. The guard has to live
 * somewhere that parses, and index.js must not be required until it passes.
 */

/** Oldest Node the wizard's own syntax and APIs require. Keep in sync with `engines.node`. */
var MIN_MAJOR = 18;

/**
 * Explain, actionably, why this Node cannot run the wizard.
 *
 * @param {string} version - `process.versions.node`, e.g. "12.22.9"
 * @returns {string|null} a ready-to-print message, or null when the version is fine
 */
function unsupportedMessage(version) {
  var major = parseInt(String(version).split('.')[0], 10);
  var shown = version ? 'v' + version : 'an unknown version';

  // An unrecognisable version is treated as unsupported on purpose: proceeding
  // risks the SyntaxError this guard exists to replace, and the message below
  // is useful either way.
  if (!isNaN(major) && major >= MIN_MAJOR) return null;

  return (
    'sysknife-setup needs Node ' + MIN_MAJOR + ' or newer. You are running ' + shown + '.\n' +
    '\n' +
    "Ubuntu 22.04's `apt install nodejs` gives Node 12, which cannot run this\n" +
    'installer. Pick whichever of these suits the machine:\n' +
    '\n' +
    '  system-wide (needs root):\n' +
    '    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -\n' +
    '    sudo apt-get install -y nodejs\n' +
    '\n' +
    '  just for you (no root):\n' +
    '    curl -fsSL https://fnm.vercel.app/install | bash && fnm install 22\n' +
    '\n' +
    '  snap (no root prompt on most Ubuntu desktops):\n' +
    '    sudo snap install node --classic --channel=22\n' +
    '\n' +
    'Or skip Node entirely: the release page ships prebuilt binaries, and\n' +
    'docs/quickstart.md covers installing them by hand.\n' +
    '  https://github.com/lacs-project/sysknife/releases/latest\n'
  );
}

module.exports = { unsupportedMessage: unsupportedMessage, MIN_MAJOR: MIN_MAJOR };
