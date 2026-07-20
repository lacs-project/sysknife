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
  try {
    if (fs.existsSync(filePath)) {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        existing = parsed;
      }
    }
  } catch {
    // Malformed JSON — start from an empty config rather than crashing the wizard.
    existing = {};
  }
  const existingServers =
    existing.mcpServers && typeof existing.mcpServers === 'object' ? existing.mcpServers : {};
  return { ...existing, mcpServers: { ...existingServers, ...servers } };
}

module.exports = { mergeMcpServers };
