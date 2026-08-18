'use strict';

// Merge SysKnife's MCP server entries into an existing client config instead of
// overwriting the whole file. A plain `{ mcpServers }` write clobbered any other
// MCP servers the user had configured (Claude Code's `.mcp.json`, Cursor's
// `.cursor/mcp.json`); this preserves them and every other top-level key.

const fs = require('fs');

/**
 * Return an MCP config object with `servers` merged under `mcpServers`,
 * preserving any existing servers and unrelated top-level keys. A missing,
 * empty, or whitespace-only file is treated as an empty config; an unreadable,
 * malformed, or non-object existing file is refused so the caller cannot
 * overwrite user-managed MCP entries.
 *
 * @param {string} filePath  path to the client's MCP config JSON
 * @param {Record<string, unknown>} servers  the sysknife server entries to upsert
 * @returns {Record<string, unknown>} the merged config, ready to JSON.stringify
 */
function mergeMcpServers(filePath, servers) {
  let existing = {};
  if (fs.existsSync(filePath)) {
    let raw;
    try {
      raw = fs.readFileSync(filePath, 'utf8');
    } catch (e) {
      // A read failure is NOT the same as malformed JSON. Treating EACCES,
      // EIO, or a symlink loop as "start empty" makes the caller write a
      // fresh file over the top, silently deleting every other MCP server the
      // user had configured — the exact clobbering this function exists to
      // prevent. Refuse instead.
      throw new Error(
        `could not read existing MCP config at ${filePath}: ${e.message} — ` +
          'refusing to overwrite it, since that would discard your other MCP servers'
      );
    }

    // Editors commonly preserve a UTF-8 BOM even though JSON.parse does not
    // accept it. An empty file is also a normal placeholder state, so treat it
    // the same as a file that has not been created yet.
    const json = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
    if (json.trim() !== '') {
      let parsed;
      try {
        parsed = JSON.parse(json);
      } catch (e) {
        // Some Node versions quote the unexpected source token in e.message.
        // MCP config files may contain provider API keys, so retain only the
        // useful location clause and never echo source text into stderr/logs.
        const message = String(e && e.message ? e.message : '');
        const location = message.match(/at position \d+(?: \(line \d+ column \d+\))?/i);
        throw new Error(
          `existing MCP config at ${filePath} is malformed JSON${location ? ` ${location[0]}` : ''} — ` +
            'refusing to overwrite it; fix or move the file and run setup again'
        );
      }

      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error(
          `existing MCP config at ${filePath} must contain a JSON object — ` +
            'refusing to overwrite it; fix or move the file and run setup again'
        );
      }
      existing = parsed;
    }
  }
  const existingServers =
    existing.mcpServers && typeof existing.mcpServers === 'object' ? existing.mcpServers : {};
  return { ...existing, mcpServers: { ...existingServers, ...servers } };
}

module.exports = { mergeMcpServers };
