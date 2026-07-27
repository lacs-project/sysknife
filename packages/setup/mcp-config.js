'use strict';

// Merge SysKnife's MCP server entries into an existing client config instead of
// overwriting the whole file. A plain `{ mcpServers }` write clobbered any other
// MCP servers the user had configured (Claude Code's `.mcp.json`, Cursor's
// `.cursor/mcp.json`); this preserves them and every other top-level key.

const fs = require('fs');

/**
 * Return an MCP config object with `servers` merged under `mcpServers`,
 * preserving any existing servers and unrelated top-level keys. A missing or
 * unparseable file is treated as an empty config (never throws).
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
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        existing = parsed;
      }
    } catch {
      // Malformed JSON — start from an empty config rather than crashing the
      // wizard. There is nothing to preserve in a file we cannot parse.
      existing = {};
    }
  }
  const existingServers =
    existing.mcpServers && typeof existing.mcpServers === 'object' ? existing.mcpServers : {};
  return { ...existing, mcpServers: { ...existingServers, ...servers } };
}

module.exports = { mergeMcpServers };
