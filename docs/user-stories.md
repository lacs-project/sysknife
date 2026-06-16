# SysKnife User Stories — End-to-End Code Trace

Ten user stories from the perspective of sysadmins, developers, and
Linux enthusiasts. Each story traces the request through every layer
of the stack: shell UI → Tauri backend → brain (LLM) → daemon →
system.

---

## Story 1: Sysadmin layers vim on Silverblue

**Persona:** Sysadmin managing a fleet of Silverblue workstations.

**Intent:** "Install vim as a layered package"

**E2E trace:**

1. **IntentPane** (`apps/sysknife-shell/src/components/IntentPane.tsx`)
   User types intent, clicks Submit → dispatches `intent_submitted`.

2. **daemonBridge** (`apps/sysknife-shell/src/daemonBridge.ts:10`)
   `requestPlan(intent)` → Tauri IPC `invoke("plan_intent", { intent })`.

3. **Tauri command** (`apps/sysknife-shell/src-tauri/src/commands.rs:204`)
   `plan_intent()` → `execute_plan_intent()` calls
   `state.planner.plan_intent(intent)`.

4. **LLM planning loop** (`crates/sysknife-brain/src/planner.rs:318`)
   Turn 0: LLM receives system prompt (97 actions, risk rules) +
   user message. LLM calls `get_system_state`.

5. **State injection** (`crates/sysknife-brain/src/planner.rs:366`)
   `state_client.curated_state()` → daemon IPC → `collect_state()`
   (`crates/sysknife-daemon/src/state_collector.rs:48`) runs `hostname`,
   `rpm-ostree status`, `systemctl list-units`, `flatpak list`,
   `toolbox list`. Returns JSON with host, deployment, services,
   flatpaks, toolboxes.

6. **LLM proposes plan** — calls `propose_plan` with:
   ```json
   {"summary": "Layer vim via rpm-ostree",
    "explanation": "This layers the vim package...",
    "steps": [{"action_name": "InstallPackages",
               "summary": "Layer vim",
               "risk_level": "high",
               "params": {"packages": ["vim"]}}]}
   ```

7. **Safety fence** (`crates/sysknife-brain/src/planning_tools/propose_plan.rs:204`)
   `ActionName::parse("InstallPackages")` → OK (in KNOWN\_ACTIONS).
   Risk "high" → `PlanRiskLevel::High`. `PlanStep::new()` succeeds.

8. **Plan returned** to shell as `PlanResponse`
   (`commands.rs:336` `plan_to_response()`).

9. **PlanPane** (`apps/sysknife-shell/src/components/PlanPane.tsx`)
   Shows step "InstallPackages" with red HIGH badge. Aggregate risk =
   high → user must type "InstallPackages" to confirm.

10. **Approval** → `requestApproval(steps)` → Tauri `approve_preview`.

11. **Daemon preview** (`crates/sysknife-daemon/src/dispatcher.rs:440`)
    `handle_preview("InstallPackages", params)` → calls
    `preview_action()` → returns risk=High, rollback\_available=true,
    side\_effects, request\_hash.

12. **Daemon execute** (`crates/sysknife-daemon/src/dispatcher.rs:535`)
    Validates approval\_hash == request\_hash. Calls
    `build_action_spec("InstallPackages", params)`
    (`crates/sysknife-daemon/src/executor.rs:63`) → builds
    `rpm-ostree install vim`. Executes via `execute_spec()`. Streams
    stdout lines as `JobProgress` frames.

13. **Live output** → shell emits `sysknife:timeline-entry` events →
    ExecutionPane shows live log.

14. **Completion** → `sysknife:job-completed` with `succeeded` or
    `needs_reboot`. Transaction persisted to SQLite.

**Gap identified:** The LLM sees `flatpaks` and `services` but not
the list of already-layered packages (`GetLayeredPackages` output).
It could propose installing a package that is already layered. The
LLM would need to call `get_system_state` and receive layered
package info to avoid this.

---

## Story 2: Developer rebases to Fedora 42

**Persona:** Developer on Silverblue who wants to upgrade.

**Intent:** "Rebase this system to Fedora 42"

**E2E trace:**

1. Intent → `plan_intent` → LLM calls `get_system_state`, sees
   `deployment: "fedora/41"`.

2. LLM proposes:
   ```json
   {"steps": [
     {"action_name": "RebaseSystem", "risk_level": "high",
      "params": {"ref": "fedora:fedora/42/x86_64/silverblue"}},
     {"action_name": "RebootSystem", "risk_level": "high",
      "params": {}}
   ]}
   ```

3. Safety fence: both actions in KNOWN\_ACTIONS, both high risk. Valid.

4. PlanPane: two steps, both HIGH. User types "RebaseSystem" to
   approve.

5. Daemon executes `rpm-ostree rebase fedora:fedora/42/x86_64/silverblue`.
   Live output streams download progress. If rebase fails,
   `rollback_spec_for("RebaseSystem")` triggers
   `rpm-ostree rollback` automatically
   (`crates/sysknife-daemon/src/executor.rs` rollback path).

6. Job completes with `needs_reboot`. ExecutionPane shows reboot
   banner.

**Gap identified:** The LLM hardcodes the ostree ref string in
params. There is no tool to query available refs or validate that
`fedora/42` exists before proposing the rebase. A
`ListAvailableRefs` action would prevent plans that fail at
execution.

---

## Story 3: Sysadmin checks what is running

**Persona:** On-call sysadmin investigating a slow system.

**Intent:** "Show me all running services and installed flatpaks"

**E2E trace:**

1. LLM receives intent. Calls `get_system_state` — gets services
   and flatpaks from CuratedState. But this is a summary, not the
   full list.

2. LLM proposes:
   ```json
   {"steps": [
     {"action_name": "ListServices", "risk_level": "low", "params": {}},
     {"action_name": "SearchFlatpakApps", "risk_level": "low", "params": {}}
   ]}
   ```

3. Both low risk → `approval_required = false`. Plan auto-executes
   (no gate).

4. Daemon runs `systemctl list-units --type=service --state=running`
   and `flatpak list`. Output streams to timeline.

5. User sees full output in ExecutionPane live log.

**Gap identified:** Low-risk read-only plans still go through the
full approval pipeline even though no mutation occurs. The UX could
short-circuit to show results inline without the execution pane
ceremony. Also, the LLM does not receive the *output* of these
commands — it only proposes them. The user sees the output, but the
LLM cannot reason about what it found (no feedback loop for
read-only queries).

---

## Story 4: Developer sets up a toolbox for Rust development

**Persona:** Developer who wants an isolated dev environment.

**Intent:** "Create a new toolbox called rust-dev and enter it"

**E2E trace:**

1. LLM proposes:
   ```json
   {"steps": [
     {"action_name": "CreateToolbox", "risk_level": "medium",
      "params": {"name": "rust-dev"}}
   ]}
   ```
   (`EnterToolbox` was removed — the LLM will not propose it.)

2. Medium risk. PlanPane shows an orange MEDIUM badge. User checks
   "I understand this will modify system state" and clicks Approve.

3. Daemon runs `toolbox create rust-dev`. The plan completes after
   creation.

4. `EnterToolbox` was removed from the action catalogue because
   entering a toolbox is an interactive TTY operation that the daemon
   cannot perform on behalf of the user. The LLM will not propose
   this step.

**Note:** `EnterToolbox` was removed (not deferred) after review
determined that the daemon cannot meaningfully execute an interactive
shell session.

---

## Story 5: Sysadmin hardens firewall rules

**Persona:** Security-conscious sysadmin.

**Intent:** "Allow SSH and block everything else on the firewall"

**E2E trace:**

1. LLM calls `get_system_state`, sees current services and
   firewall state (via `GetFirewallState` if it proposes that first).

2. LLM proposes:
   ```json
   {"steps": [
     {"action_name": "GetFirewallState", "risk_level": "low",
      "params": {}},
     {"action_name": "ConfigureFirewall", "risk_level": "medium",
      "params": {"action": "add_service", "service": "ssh"}}
   ]}
   ```

3. Problem: the LLM can only add/remove services one at a time.
   "Block everything else" requires knowledge of what is currently
   allowed, then removing each service. The LLM cannot see the
   output of step 1 (`GetFirewallState`) before proposing step 2 —
   all steps are proposed in a single `propose_plan` call.

**Gap identified:** The planning model is single-shot: the LLM
proposes all steps at once without seeing intermediate execution
results. For iterative workflows ("check state, then decide what to
change"), the LLM would need a multi-round planning capability where
step outputs feed back into subsequent planning.

---

## Story 6: Linux enthusiast explores the system

**Persona:** Curious Fedora user who just installed SysKnife.

**Intent:** "What containers are running and what flatpaks do I have?"

**E2E trace:**

1. LLM proposes two low-risk read-only steps:
   `ListContainers` + `SearchFlatpakApps` (or `ListFlatpakRemotes`).

2. No approval required. Daemon runs `podman ps` and `flatpak list`.

3. User sees container and flatpak listing in the timeline.

**What works well:** The zero-friction path for read-only queries is
good. Low risk = no checkbox, no typing. The user just asks and
gets answers.

**What could be better:** The output appears as raw command stdout
in the timeline. The LLM could summarize or format the output if it
had access to it after execution. Currently it is a "fire and
forget" model — the LLM never sees what the commands produced.

---

## Story 7: Sysadmin creates a service account

**Persona:** Sysadmin provisioning a new CI runner.

**Intent:** "Create a user called ci-runner and add it to the docker group"

**E2E trace:**

1. LLM proposes:
   ```json
   {"steps": [
     {"action_name": "CreateUser", "risk_level": "medium",
      "params": {"username": "ci-runner"}},
     {"action_name": "AddUserToGroup", "risk_level": "high",
      "params": {"username": "ci-runner", "group": "docker"}}
   ]}
   ```

2. CreateUser = medium (Dev role), AddUserToGroup = high (Admin
   role). Mixed risk. Aggregate = high. User types
   "AddUserToGroup" to confirm.

3. Daemon input validation (`crates/sysknife-daemon/src/actions/validate.rs`)
   checks `validated_username("ci-runner")` and
   `validated_group("docker")` — rejects shell metacharacters.

4. Daemon runs `sudo useradd ci-runner` then
   `sudo usermod -aG docker ci-runner`.

5. Transaction logged to SQLite with both action names, params,
   caller role, and timestamps.

**What works well:** The role-based authorization
(`crates/sysknife-daemon/src/policy.rs:24`) ensures the caller has
Admin rights for `AddUserToGroup`. The input validation prevents
injection (e.g., `ci-runner; rm -rf /`).

---

## Story 8: Developer rolls back a failed update

**Persona:** Developer whose system broke after an update.

**Intent:** "Roll back to the previous deployment"

**E2E trace:**

1. LLM calls `get_system_state`, sees current deployment.

2. LLM proposes:
   ```json
   {"steps": [
     {"action_name": "RollbackDeployment", "risk_level": "high",
      "params": {}},
     {"action_name": "RebootSystem", "risk_level": "high",
      "params": {}}
   ]}
   ```

3. User types "RollbackDeployment" to confirm.

4. Daemon runs `rpm-ostree rollback`. If this succeeds, proceeds
   to `RebootSystem` (`systemctl reboot`).

5. If `RollbackDeployment` fails, the automatic rollback mechanism
   (`executor.rs` `rollback_spec_for`) tries to roll back the
   rollback — which in this case means `rpm-ostree rollback` again,
   returning to the current state. The job transitions to
   `RolledBack` state.

**What works well:** The rollback-of-rollback semantic is correct
for deployment actions since `rpm-ostree rollback` is its own
inverse.

---

## Story 9: Sysadmin pins the current deployment before experimenting

**Persona:** Cautious sysadmin about to try something risky.

**Intent:** "Pin the current deployment so I can experiment safely"

**E2E trace:**

1. LLM calls `get_system_state`, sees deployment info.

2. LLM proposes:
   ```json
   {"steps": [
     {"action_name": "PinDeployment", "risk_level": "high",
      "params": {"index": 0}}
   ]}
   ```

3. `index: 0` refers to the booted deployment. Daemon runs
   `rpm-ostree pin 0`.

4. User sees confirmation in timeline. Deployment is now pinned
   and cannot be garbage-collected.

**Gap identified:** The LLM has to guess that `index: 0` is the
current deployment. The `CuratedState` includes deployment info
but not the index. A more robust approach would be for the LLM to
first call `ListDeployments` and use the output — but again, the
single-shot planning model prevents this.

---

## Story 10: First-time user with no LLM configured

**Persona:** Curious developer who just cloned and built SysKnife.

**Intent:** (none yet — first launch)

**E2E trace:**

1. **App mount** (`apps/sysknife-shell/src/App.tsx`)
   `checkSetupStatus()` → Tauri command → `commands.rs:363`
   `config_path_exists()` checks `~/.config/sysknife/config.toml`,
   `provider_is_configured()` checks env vars and config.

2. If neither is set → `needsSetup = true` → **SetupWizard**
   (`apps/sysknife-shell/src/components/SetupWizard.tsx`) renders.

3. **Step 1:** User picks Ollama (recommended, no API key) or
   Anthropic.

4. **Step 2:** Wizard shows config.toml content to copy. For
   Ollama: reminds user to `ollama pull llama3.2`.

5. **Step 3:** "Restart the shell to apply."

6. After restart, `BrainConfig::from_env()`
   (`crates/sysknife-brain/src/config.rs:96`) auto-detects Ollama
   (no `ANTHROPIC_API_KEY` → fallback to Ollama provider).

7. `LlmPlanner::from_config()` (`crates/sysknife-brain/src/planner.rs:287`)
   constructs `OllamaProvider` with `http://localhost:11434` and
   model `llama3.2`.

8. User can now type intents. Header shows
   "via ollama / llama3.2".

**What works well:** Zero-API-key path with Ollama is a strong
onboarding story for privacy-conscious sysadmins.

**Gap identified:** If Ollama is not running, the error is
`llm_http_error` with a connection-refused message. The wizard
does not verify that Ollama is actually reachable before marking
setup as complete.

---

## Summary of Gaps Found

| # | Gap | Impact | Severity |
|---|-----|--------|----------|
| 1 | CuratedState lacks layered package list | LLM may propose installing already-layered packages | Medium |
| 2 | No tool to query available ostree refs | Rebase plans can reference non-existent refs | Medium |
| 3 | No feedback loop — LLM cannot see command output | Cannot do iterative "check then act" workflows | High |
| 4 | ~~EnterToolbox is not interactive-TTY-aware~~ | Resolved: action removed from catalogue | — |
| 5 | Single-shot planning — all steps proposed at once | Cannot adapt plan based on intermediate results | High |
| 6 | Raw stdout in timeline, no LLM summarization | Read-only queries produce unformatted output | Low |
| 7 | SetupWizard does not verify Ollama reachability | User completes setup but gets connection errors | Low |
| 8 | System prompt says "Fedora Silverblue" only | Misleading once multi-distro ships | Low |
