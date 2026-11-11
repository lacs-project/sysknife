'use strict';

// Keep the installer and uninstaller on one source of truth. Uninstall only
// removes these files when their contents still match what setup generated.
const CLAUDE_HOOKS = {
  'hookify.require-sysknife-approval.local.md': `---
name: require-sysknife-approval
enabled: true
event: prompt
pattern: .*
---

# SysKnife execution rules (always active)

## Single VM

When using the sysknife MCP tools, you MUST follow this order:

1. Call \`sysknife_plan\` and present every transaction ID to the user
2. **STOP.** The user must run \`sysknife approve <transaction-id>\` in a terminal
3. Ask the user to provide each one-time receipt printed by that command
4. Call \`sysknife_execute\` only with the matching \`approval_receipt\`

**Never call \`sysknife_execute\` in the same turn as \`sysknife_plan\`.**
A chat response such as "yes" is not approval and cannot replace a receipt.

## Multiple VMs (fleet operations)

When sysknife is configured with multiple targets (sysknife-web, sysknife-db, …):

1. Call \`sysknife_plan\` for **all** VMs that will be affected — before executing any
2. Present **all** plans together so the user can review the full scope of changes
3. **STOP** while the user runs \`sysknife approve <transaction-id>\` for every accepted step
4. Collect the matching terminal-issued receipts, then execute each VM

**Never execute one VM while another VM's plan is still pending review.**
**Never skip showing a plan because it looks similar to another VM's plan.**
Each VM is independent — show each plan explicitly.
`,
  'hookify.sysknife-schema-fetch.local.md': `---
name: sysknife-schema-fetch
enabled: true
event: prompt
pattern: .*
---

# Deferred MCP tool schemas must be fetched before use

Sysknife MCP tools (\`sysknife_plan\`, \`sysknife_execute\`) are registered as
**deferred tools** — their full schemas are NOT loaded at session start to
save context.

**Before calling any sysknife tool you have not used yet this session:**
1. Call \`ToolSearch\` with the tool name (e.g. \`select:sysknife_plan\`) to fetch its schema.
2. Only then call the tool.

Skipping this step causes \`InputValidationError\` because the parameter schema is unknown.
`,
  'hookify.sysknife-bash-guard.local.md': `---
name: sysknife-bash-guard
enabled: true
event: bash
pattern: (?:date|hostname|uname|df|free|uptime|who|id|ps|top|systemctl|journalctl|ip\\s|ss\\s|netstat|lscpu|lsmem|cat\\s+/proc|dmidecode)
---

# Route VM system queries through sysknife — not local Bash

The command you are about to run queries system state.  If the user is asking
about their **QEMU/KVM guest VM**, this local Bash command returns host data —
not VM data.

**Before running local Bash for system queries:**
1. Check whether sysknife MCP tools are available (fetch deferred schemas via \`ToolSearch\`).
2. If sysknife is available, use \`sysknife_plan\` → terminal \`sysknife approve\` → \`sysknife_execute\` instead.
3. Only run the local Bash command if sysknife is unavailable or the user explicitly asks for the local host.
`,
};

module.exports = { CLAUDE_HOOKS };
