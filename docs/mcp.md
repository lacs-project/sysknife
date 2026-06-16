# SysKnife MCP Server

The `sysknife mcp-server` subcommand exposes two MCP tools that let any
MCP-capable AI assistant (Claude Code, Cursor, Codex CLI, …) plan and execute
Linux system administration tasks through SysKnife's approval-gated,
audit-logged path.

<img
  src="https://raw.githubusercontent.com/lacs-project/sysknife/main/assets/demo/mcp-flow.gif"
  alt="SysKnife MCP flow — Claude Code plans, user approves, daemon executes"
  class="sysknife-demo"
/>

> **💡 One command to configure everything**
>
> Run `npx sysknife-setup` — it detects which AI clients you have installed and
> writes the correct config files for each one automatically.

---

## Tools

### `sysknife_plan`

Turn a natural-language intent into a risk-labelled plan.  No action is
executed.

**Input**

| Field    | Type   | Description                              |
|----------|--------|------------------------------------------|
| `intent` | string | Natural-language intent, e.g. `"check disk usage"` |

**Output** — `PlanOutput`

| Field         | Type            | Description                              |
|---------------|-----------------|------------------------------------------|
| `intent`      | string          | The original intent                      |
| `summary`     | string          | One-line plan summary                    |
| `explanation` | string          | Why this plan was chosen                 |
| `steps`       | `PlanStep[]`    | Ordered steps to execute                 |

Each `PlanStep`:

| Field         | Type   | Description                              |
|---------------|--------|------------------------------------------|
| `action_name` | string | Canonical action name, e.g. `GetDiskUsage` |
| `summary`     | string | What this step does                      |
| `risk_level`  | string | `"low"`, `"medium"`, or `"high"`         |
| `params`      | object | Action-specific parameters               |
| `command`     | string | Resolved shell command, e.g. `"timedatectl"` (empty if daemon unreachable) |

---

### `sysknife_execute`

Execute a plan produced by `sysknife_plan`.  Pass the `steps` array
unchanged.

**Input**

| Field      | Type          | Description                                      |
|------------|---------------|--------------------------------------------------|
| `steps`    | `StepToExecute[]` | Steps from `sysknife_plan` output              |
| `max_risk` | string?       | Ceiling: `"low"`, `"medium"` (default), `"high"` |

Steps whose daemon-assessed risk exceeds `max_risk` cause an error
before any execution begins.  Execution halts on the first failure.

**Output** — `ExecuteOutput`

| Field          | Type           | Description                        |
|----------------|----------------|------------------------------------|
| `steps`        | `StepResult[]` | Per-step results                   |
| `needs_reboot` | bool           | True if any step requires a reboot |

Each `StepResult`:

| Field            | Type       | Description                              |
|------------------|------------|------------------------------------------|
| `action_name`    | string     | Action that was executed                 |
| `status`         | string     | `"succeeded"`, `"failed"`, etc.          |
| `summary`        | string     | Human-readable outcome                   |
| `output`         | `string[]` | Progress lines (ANSI stripped)           |
| `warnings`       | `string[]` | Daemon warnings                          |
| `needs_reboot`   | bool       | Whether this step needs a reboot         |
| `transaction_id` | string     | Daemon audit transaction ID              |

---

## The Approval Workflow

**The assistant must always follow this order — no exceptions:**

```text
1. sysknife_plan { intent }
        ↓
   Present the plan (steps + risk levels) to the user
        ↓
2. WAIT for explicit user approval
   ("yes", "do it", "execute", "go ahead", "approved")
        ↓
3. sysknife_execute { steps, max_risk }
        ↓
   Report results
```

**Never call `sysknife_execute` in the same turn as `sysknife_plan`.**  The plan
must be shown and the user must respond before any execution occurs.

This rule is enforced by the hookify prompt hook in
`.claude/hookify.require-sysknife-approval.md`, which injects a reminder
into the assistant's context on every turn.

---

## Setup

### 1. Run the setup wizard

```sh
npx sysknife-setup
```

The wizard detects your installed `sysknife` binary, asks for the daemon
socket and LLM provider, and then asks which integration to configure.
No manual file editing needed.

If you already know the target, skip the picker:

```sh
npx sysknife-setup --claude
npx sysknife-setup --cursor
npx sysknife-setup --codex
```

`.mcp.json` is gitignored — it contains secrets and local paths.

### 2. Connect to a daemon in a VM

If the daemon runs inside a VM, two transports are available:

**SSH socket tunnel** (works with any hypervisor):

```sh
ssh -fN -L /tmp/sysknife-vm.sock:/run/sysknife/daemon.sock \
    <user>@<vm-host>
```

Set `SYSKNIFE_SOCKET=/tmp/sysknife-vm.sock` when the setup wizard asks for
the socket path.

**virtio-vsock** (KVM/QEMU only, no SSH required):

```sh
# Find the guest CID from the host
virsh dumpxml <vm-name> | grep cid
```

Set `SYSKNIFE_SOCKET=vsock://<CID>:9734` and `SYSKNIFE_TOKEN=<hex>` when
the wizard asks. The wizard detects the `vsock://` prefix and prompts for
the token automatically.

See [VM + Daemon Setup](vm-daemon-setup.md) for the complete walkthrough
including token generation, libvirt XML, and troubleshooting.

### 3. Manual configuration

If you prefer to edit `.mcp.json` by hand:

```json
{
  "mcpServers": {
    "sysknife": {
      "command": "/path/to/sysknife",
      "args": ["mcp-server"],
      "env": {
        "SYSKNIFE_SOCKET": "/run/sysknife/daemon.sock",
        "SYSKNIFE_LLM_PROVIDER": "openai",
        "OPENAI_API_KEY": "<your-api-key>",
        "SYSKNIFE_LLM_MODEL": "gpt-4.1"
      }
    }
  }
}
```

For vsock add `SYSKNIFE_TOKEN` alongside `SYSKNIFE_SOCKET`.

### 4. Build the binary

```sh
cargo build -p sysknife-cli --release
# binary at target/release/sysknife
```

### 5. Reload the MCP server in your client

In Claude Code: run `/reload-plugins`.

---

## Example Session

```text
User:    check disk usage on the VM

Claude:  [calls sysknife_plan { intent: "check disk usage" }]

         Plan: Check disk usage on all filesystems
         Steps:
           ● low  GetDiskUsage — Retrieve current disk usage

         Execute?

User:    yes

Claude:  [calls sysknife_execute { steps: [...], max_risk: "low" }]

         GetDiskUsage ✓
         Filesystem     Size  Used Avail Use%  Mounted on
         /dev/vda3       38G   18G   19G  49%  /var
         ...
```

---

## Risk Levels

| Level    | Meaning                                         | Default ceiling |
|----------|-------------------------------------------------|-----------------|
| `low`    | Read-only or fully reversible                   | Always allowed  |
| `medium` | Modifies state but reversible (e.g. set timezone) | Allowed by default |
| `high`   | Destructive or hard to reverse (e.g. rpm-ostree) | Requires `max_risk: "high"` |

Set `max_risk` explicitly when you know the plan contains high-risk
steps and the user has approved them.
