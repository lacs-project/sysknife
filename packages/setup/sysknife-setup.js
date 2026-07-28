#!/usr/bin/env node
'use strict';

/**
 * sysknife-setup.js — the `npx sysknife-setup` entrypoint.
 *
 * This exists only to check the Node version before `index.js` is loaded.
 * `index.js` uses syntax that Node 12 (Ubuntu 22.04's apt default) cannot
 * parse, and a parse error is raised for the whole module before any statement
 * in it runs — so the check cannot live there. It also cannot rely on
 * `engines.node`, which npx reports as a warning and then ignores.
 *
 * Keep this file parseable by Node 12: no `?.`, no `??`, no logical assignment.
 * tests/node-preflight.test.mjs enforces that, and enforces that the check
 * happens before the require below.
 */

var preflight = require('./node-preflight.js');

var problem = preflight.unsupportedMessage(process.versions.node);
if (problem) {
  process.stderr.write('\n' + problem + '\n');
  process.exit(1);
}

require('./index.js');
