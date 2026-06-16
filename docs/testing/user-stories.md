# SysKnife E2E User Stories

Twenty scenarios for validating SysKnife on a real Fedora Atomic Desktop (Silverblue,
Kinoite, Sway Atomic, Budgie Atomic, or COSMIC Atomic). Run inside a QEMU/KVM
VM via `tests/e2e/atomic-vm.sh`, or on real hardware.

Each story has:

- **Intent** — what the user types into the shell
- **Expected LLM behavior** — which query tools it should call, what plan it
  should propose
- **Automated** — whether the `run-stories.sh` harness exercises it
- **Pass criteria** — concrete conditions for success
- **Cleanup** — how to revert any system changes

The **automated** stories (1–7, 11–17) are also covered by the container-based
CI smoke test (see `.github/workflows/e2e.yml`). The **semi-automated** stories
(8–10, 18–20) make real system changes and only run when
`SYSKNIFE_ALLOW_DESTRUCTIVE=1` is set — take a VM snapshot first via
`atomic-vm.sh snapshot pre-destructive`.

---

## Story 1: Check disk usage

**Persona:** Sysadmin triaging a full disk alert.

**Intent:** `"show me disk usage for all mounted filesystems"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — no query tools needed for a direct read request
- Proposes a single-step plan: `GetDiskUsage` (Low risk, no approval required)

**Automated:** yes (read-only)

**Pass criteria:**
- Plan has exactly 1 step, `GetDiskUsage`, risk `low`, `approvalRequired: false`
- Execution returns at least one line matching `/^\/dev\/\S+/` (a real device)
- Execution completes in under 15 seconds

**Cleanup:** none (read-only)

---

## Story 2: Memory pressure diagnosis

**Persona:** Developer whose laptop is sluggish.

**Intent:** `"is the system low on memory? show me what's using it"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — phrased as a question but still a direct
  read request; no query tools needed
- Proposes a 2-step plan: `GetMemoryInfo` + `ListProcesses`
- Both steps Low risk, no approval required

**Automated:** yes

**Pass criteria:**
- Plan has 2 steps, both risk `low`
- One step is `GetMemoryInfo`, one is `ListProcesses`
- Execution output contains `Mem:` (from `free -h`)
- Execution output contains `PID` (from `ps aux` header)

**Cleanup:** none

---

## Story 3: Service health check

**Persona:** On-call engineer verifying a service.

**Intent:** `"is sshd running? show me its recent logs"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` with `ListServices` + `GetServiceLogs`
- Does NOT need to call `query_services` or `query_logs` first — the intent
  explicitly asks for both the service status and its logs
- `GetServiceLogs` step carries `params.unit = "sshd.service"`

**Automated:** yes

**Pass criteria:**
- Plan includes `GetServiceLogs` with `unit` parameter set to `sshd.service` or
  `sshd` (the LLM may or may not add `.service`)
- Execution output contains journal-style log lines
- Execution completes under 20 seconds

**Cleanup:** none

---

## Story 4: Firewall inspection

**Persona:** Security-conscious user before opening a port.

**Intent:** `"what ports are currently open on the firewall?"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — direct read request, no decision needed
- Proposes a plan with `GetFirewallState` (Low risk)

**Automated:** yes

**Pass criteria:**
- Plan has 1 step, `GetFirewallState`
- Execution completes without error
- Output contains one of: `services:`, `ports:`, `public (active)`, or similar
  firewalld/iptables markers

**Cleanup:** none

---

## Story 5: List layered packages

**Persona:** Power user recalling what they installed.

**Intent:** `"what packages have I layered on top of the base system?"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — direct read request, no decision needed
- Proposes `GetLayeredPackages` (Low risk)

**Automated:** yes

**Pass criteria:**
- Plan has 1 step, `GetLayeredPackages`
- Execution completes; empty output is acceptable (no layered packages is a
  valid state)

**Cleanup:** none

---

## Story 6: Running containers overview

**Persona:** Developer checking their podman workflow.

**Intent:** `"list all running containers and show me which services are up"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — intent explicitly asks for both containers
  and services; no decision to be made
- Proposes a 2-step plan: `ListContainers` + `ListServices`

**Automated:** yes

**Pass criteria:**
- Plan has 2 steps, both risk `low`
- `ListContainers` and `ListServices` both present
- Execution output contains `NAMES` (podman ps header) and service names

**Cleanup:** none

---

## Story 7: SSH key inventory

**Persona:** Sysadmin auditing SSH access for a user.

**Intent:** `"show me the SSH keys authorized for user lacsdev"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — direct read request with explicit username
- Proposes `GetAuthorizedKeys` with `params.username = "lacsdev"`

**Automated:** yes

**Pass criteria:**
- Plan has 1 step, `GetAuthorizedKeys`
- `params.username == "lacsdev"` (the test VM has this user pre-provisioned)
- Execution returns the pre-seeded public key (an `ssh-ed25519 AAAA...` line)

**Cleanup:** none

---

## Story 8 (destructive): Layer vim via rpm-ostree

**Persona:** Developer who just realized vim isn't installed.

**Intent:** `"install vim as a layered package"`

**Expected LLM behavior:**
- May call `query_packages` first to check if vim is already layered
- Proposes `InstallPackages` (or `AddLayeredPackage`) with `packages: ["vim"]`
- Plan marked `approvalRequired: true`, risk `high`

**Automated:** only with `SYSKNIFE_ALLOW_DESTRUCTIVE=1` and a VM snapshot set

**Pass criteria:**
- Plan requires approval (high risk)
- After auto-approval, daemon executes `rpm-ostree install vim`
- Execution succeeds with `needs_reboot` outcome
- `rpm-ostree status` shows vim in staged deployment layered packages

**Cleanup:** revert VM snapshot after the test

---

## Story 9 (destructive): Create a toolbox

**Persona:** Developer setting up a dev environment.

**Intent:** `"create a toolbox container called dev-test for development work"`

**Expected LLM behavior:**
- May call `query_toolboxes` first to check for name collision
- Proposes `CreateToolbox` with `name: "dev-test"`
- Plan marked `approvalRequired: true`, risk `medium`

**Automated:** only with `SYSKNIFE_ALLOW_DESTRUCTIVE=1`

**Pass criteria:**
- Plan has `CreateToolbox` step with `params.name == "dev-test"`
- After auto-approval, `toolbox list --containers` includes `dev-test`

**Cleanup:**
- Run `toolbox rm -f dev-test` in post-test cleanup
- Or revert VM snapshot

---

## Story 10 (destructive): Add SSH authorized key

**Persona:** Sysadmin provisioning a new admin's access.

**Intent:** `"authorize this SSH key for user lacsdev: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestKeyForE2ETesting testkey@example"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — explicit key and username in the intent,
  no decision needed
- Proposes `AddAuthorizedKey` with `{username: "lacsdev", public_key: "ssh-ed25519 ..."}`
- Plan marked `approvalRequired: true`, risk `medium`
- The public_key param must NOT be truncated or modified

**Automated:** only with `SYSKNIFE_ALLOW_DESTRUCTIVE=1`

**Pass criteria:**
- Plan has exactly the `AddAuthorizedKey` step
- `params.public_key` matches the user's input verbatim
- After auto-approval, `/home/lacsdev/.ssh/authorized_keys` contains the key
- Idempotency: running the same story twice does not duplicate the entry

**Cleanup:**
- Run `RemoveAuthorizedKey` with the same key, OR
- Revert VM snapshot

---

## Story 11: Deployment status + kernel arguments

**Persona:** Developer curious about the booted OSTree commit and boot configuration.

**Intent:** `"show me the current deployment status and what kernel arguments are set"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — two independent read-only requests, no
  decision needed
- Proposes a 2-step plan: `ListDeployments` + `GetKernelArguments` (either order)
- Both steps Low risk, no approval required

**Automated:** yes (read-only)

**Pass criteria:**
- Plan has exactly 2 steps, both risk `low`
- Steps contain `ListDeployments` and `GetKernelArguments`

**Cleanup:** none

---

## Story 12: SysKnife activity log — today

**Persona:** Sysadmin reviewing what automation ran during the day.

**Intent:** `"show me the SysKnife activity log for today"`

**Expected LLM behavior:**
- Calls `query_job_history(since_hours: 24)` to check today's transactions
- Proposes a 1-step plan: `ListJobHistory`
- Does NOT use `get_system_state`, `query_deployments`, or any state-inspection tool

**Automated:** yes (read-only)

**Pass criteria:**
- Plan has exactly 1 step, `ListJobHistory`, risk `low`

**Cleanup:** none

---

## Story 13: Service logs for a named service

**Persona:** Admin debugging a network issue by reading firewall service logs.

**Intent:** `"show me the logs for the firewalld service"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — direct read request with an explicit service name
- Proposes `GetServiceLogs` with `params.unit = "firewalld"` (or `"firewalld.service"`)
- Does NOT call `query_services` or any other query tool first

**Automated:** yes (read-only)

**Pass criteria:**
- Plan has 1 step, `GetServiceLogs`
- `params.unit` is `"firewalld"` or `"firewalld.service"`
- Risk `low`

**Cleanup:** none

---

## Story 14: Triple compound — disk, memory, and services

**Persona:** On-call responder doing initial system health triage.

**Intent:** `"I want to check disk usage, memory pressure, and see which services are active"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — three independent read-only requests, no
  decision needed for any of them
- Proposes a 3-step plan: `GetDiskUsage` + `GetMemoryInfo` + `ListServices`
- All three steps Low risk, no approval required
- Common failure: calling `query_memory`, `query_processes`, or `get_system_state` first

**Automated:** yes (read-only)

**Pass criteria:**
- Plan has exactly 3 steps, all risk `low`
- Steps contain `GetDiskUsage`, `GetMemoryInfo`, and `ListServices`

**Cleanup:** none

---

## Story 15: Rollback history

**Persona:** Sysadmin checking whether any recent SysKnife rollbacks occurred.

**Intent:** `"show me all rollback operations SysKnife has performed"`

**Expected LLM behavior:**
- Calls `query_job_history(action_filter: "RollbackDeployment")` to consult
  the SysKnife transaction log
- Proposes `ListJobHistory` — even if the result set is empty, the user asked
  to see the log
- Does NOT use `query_deployments` or `get_system_state`

**Automated:** yes (read-only)

**Pass criteria:**
- Plan has 1 step, `ListJobHistory`, risk `low`

**Cleanup:** none

---

## Story 16: Network status + firewall

**Persona:** Admin checking connectivity and security posture together.

**Intent:** `"show me the network status and the current firewall rules"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — two independent read-only requests
- Proposes `GetNetworkStatus` + `GetFirewallState` (either order)
- All Low risk

**Automated:** yes (read-only)

**Pass criteria:**
- Plan has exactly 2 steps, both risk `low`
- Steps contain `GetNetworkStatus` and `GetFirewallState`

**Cleanup:** none

---

## Story 17: Container list + specific container info

**Persona:** Developer wanting an overview of containers plus a deep-dive on one.

**Intent:** `"list all running containers and give me detailed info on the container named 'postgres'"`

**Expected LLM behavior:**
- Goes directly to `propose_plan` — compound read request; postgres name is
  explicit, no query needed
- Proposes a 2-step plan: `ListContainers` + `GetContainerInfo`
- `GetContainerInfo` must have `params.name = "postgres"`
- Does NOT call `query_containers` first

**Automated:** yes (read-only)

**Pass criteria:**
- Plan has exactly 2 steps, both risk `low`
- `ListContainers` and `GetContainerInfo(name="postgres")` both present

**Cleanup:** none

---

## Story 18 (destructive): Restart a named service

**Persona:** Admin bouncing bluetooth after a peripheral stopped pairing.

**Intent:** `"restart the bluetooth service"`

**Expected LLM behavior:**
- Goes directly to `propose_plan`
- Proposes `RestartService` with `params.unit = "bluetooth"` (or `"bluetooth.service"`)
- Risk `medium`, approval required

**Automated:** only with `SYSKNIFE_ALLOW_DESTRUCTIVE=1`

**Pass criteria:**
- Plan has 1 step, `RestartService`, `params.unit` is `"bluetooth"` or
  `"bluetooth.service"`, risk `medium`

**Cleanup:** none (service was simply restarted)

---

## Story 19 (destructive): Full system update

**Persona:** User running weekly maintenance on their Silverblue workstation.

**Intent:** `"update my Fedora Silverblue system"`

**Expected LLM behavior:**
- Goes directly to `propose_plan`
- Proposes a single `UpdateSystem` step
- Risk `high`, approval required, reboot implied

**Automated:** only with `SYSKNIFE_ALLOW_DESTRUCTIVE=1`

**Pass criteria:**
- Plan has 1 step, `UpdateSystem`, risk `high`

**Cleanup:** rollback with `RollbackDeployment` if needed, then reboot

---

## Story 20 (destructive): Add user to privileged group

**Persona:** Admin granting sudo access to a new team member.

**Intent:** `"add the user devops to the wheel group so they can use sudo"`

**Expected LLM behavior:**
- Goes directly to `propose_plan`
- Proposes `AddUserToGroup` with `params.username = "devops"` and
  `params.group = "wheel"`
- Risk `high` (group membership changes affect privilege escalation paths)
- Approval required

**Automated:** only with `SYSKNIFE_ALLOW_DESTRUCTIVE=1`

**Pass criteria:**
- Plan has 1 step, `AddUserToGroup`, `params.username == "devops"`,
  `params.group == "wheel"`, risk `high`

**Cleanup:**
- Run `RemoveUserFromGroup` with `{username: "devops", group: "wheel"}`, or
- Revert VM snapshot

---

## Not covered by these stories (document as manual QA)

The following require real hardware or user interaction and should be covered
by the manual QA checklist (see `demo-script.md`):

- **Rollback execution** — deliberately failing a high-risk action and
  verifying automatic rollback (requires flaky hardware or fault injection)
- **RebaseSystem** — full OS upgrade (requires real network, 20+ min)
- **RebootSystem** — actual reboot (breaks VM test flow)
- **Tauri GUI rendering** — the shell's React UI (requires display server;
  covered by `pnpm test` at component level)
- **Reconnect banner on daemon crash** — covered by unit tests

## Running the stories

### Locally (real Silverblue VM, all 20 stories)

```sh
# One-time: download the Fedora Silverblue ISO and install it in QEMU/KVM
./tests/e2e/atomic-vm.sh download
./tests/e2e/atomic-vm.sh install

# Every run: boot, provision (rsyncs repo + builds SysKnife), run stories
./tests/e2e/atomic-vm.sh start
./tests/e2e/atomic-vm.sh provision
./tests/e2e/atomic-vm.sh run

# Destructive stories — snapshot first, then revert
./tests/e2e/atomic-vm.sh stop && ./tests/e2e/atomic-vm.sh snapshot clean
./tests/e2e/atomic-vm.sh start
SYSKNIFE_ALLOW_DESTRUCTIVE=1 ./tests/e2e/atomic-vm.sh run
./tests/e2e/atomic-vm.sh stop && ./tests/e2e/atomic-vm.sh restore clean
```

See [docs/contributing/testing.md](../contributing/testing.md) for
installation prerequisites, Windows instructions, and troubleshooting.

### In CI

See `.github/workflows/e2e.yml`. Triggered manually via `workflow_dispatch` or
on PRs labeled `e2e`.

### Prompt engineering observations

The system prompt in `crates/sysknife-brain/src/prompt.rs` contains three worked
examples (A, B, and C). These are **load-bearing** — removing them causes 4 of 7
read-only stories to fail with GPT-4o.

The original Example A ("check disk usage") was removed — it was a strict
subset of the prose rule and the current Example A, and added no measurable
coverage. The remaining examples were renumbered B→A, C→B. Example C
("did SysKnife successfully update recently?") was later added to teach
`query_job_history` for questions about past SysKnife actions.

Stories 8–10 require a live daemon and are skipped in the no-daemon CI run.

**Why:** Without examples, GPT-4o defaults to always querying state first
(`get_system_state` or a `query_*` tool) before proposing any plan. For
direct read-only requests this is incorrect — it either crashes the planner
(if `get_system_state` fails because the daemon is unavailable) or returns a
degraded fallback plan (e.g. `CollectDiagnostics` instead of `GetMemoryInfo`).

**The rule the examples encode:** if the user's intent maps directly to a
`Get*` or `List*` action, skip query tools entirely and call `propose_plan`
immediately. Use `query_*` only when you need to DECIDE between plans (e.g.
check if vim is already layered before proposing `AddLayeredPackage`).

| Story | Without examples | With A+B+C |
|-------|-----------------|---------|
| 1 — disk usage | ✅ (lucky fallback) | ✅ |
| 2 — memory pressure | ❌ wrong plan | ✅ |
| 3 — service health | ❌ wrong plan | ✅ |
| 4 — firewall | ❌ crash | ✅ |
| 5 — layered packages | ❌ crash | ✅ |
| 6 — containers + services | ❌ wrong plan | ✅ |
| 7 — SSH key inventory | ✅ | ✅ |
| 8 — install vim | ❌ crash (daemon absent) | ❌ crash (daemon absent) |
| 9 — create toolbox | ✅ (skipped/no-daemon) | ✅ (skipped/no-daemon) |
| 10 — add SSH key | ❌ crash (daemon absent) | ❌ crash (daemon absent) |
| 11 — deployments + kernel args | ❌ extra query step | ✅ |
| 12 — SysKnife activity log | ❌ wrong tool (deployments) | ✅ (requires Example C) |
| 13 — service logs (firewalld) | ❌ wrong plan | ✅ |
| 14 — triple compound | ❌ extra query steps | ✅ |
| 15 — rollback history | ❌ wrong tool (deployments) | ✅ (requires Example C) |
| 16 — network + firewall | ❌ wrong plan | ✅ |
| 17 — container list + detail | ❌ extra query step | ✅ |
| 18 — restart service | ❌ query first | ✅ |
| 19 — update system | ❌ query deployments first | ✅ |
| 20 — add user to group | ❌ query users first | ✅ |

**Crash** = `get_system_state` propagates `StateUnavailable` immediately;
planning returns with no plan produced.

**Wrong plan** = `query_*` errors return as tool results; model falls back
to an unrelated action (`CollectDiagnostics`, `GetDiskUsage`, etc.).

Stories 8 and 10 crash due to daemon absence regardless of examples — the
model correctly calls `query_packages` / `query_authorized_keys` (guided by
Example B), but the no-daemon environment causes those calls to error, and the
model then escalates to `get_system_state` which hard-crashes the planner.
These pass on a real VM with the daemon running.

See `CLAUDE.md` § "Prompt Engineering" for the full rule and the constraint
that prompt changes must be validated against this story suite.

### Interpreting results

`run-stories.sh` prints a summary table:

```
Story 1 (Check disk usage):            PASS (3.2s)
Story 2 (Memory pressure diagnosis):   PASS (5.1s)
Story 3 (Service health check):        FAIL (plan missing GetServiceLogs)
...
Summary: 6/7 passed
```

Each story writes detailed logs to `tests/e2e/logs/story-N.log`.
