# SysKnife Demo Script

Recording guide for the full approval + rollback demo on real
Silverblue hardware.

## Prerequisites

- Fedora Silverblue installation (VM or bare metal)
- SysKnife built and installed (`make build && sudo make install`)
- `sysknife-daemon` running (`sudo systemctl start sysknife-daemon`)
- Ollama running with `llama3.2:3b` pulled (default CPU-friendly model;
  `qwen3:8b` is only recommended if you have GPU passthrough — see
  [HACKING.md §8](../../HACKING.md))
- Terminal recorder: [asciinema](https://asciinema.org/) for the
  terminal session, or OBS/SimpleScreenRecorder for the Tauri window
- For the README GIF: [vhs](https://github.com/charmbracelet/vhs)
  or [peek](https://github.com/phw/peek)

## Scene 1: The request (10 seconds)

**Show:** the SysKnife shell window, empty state.

**Action:** type a natural-language request into the intent input:

```text
Install the htop package as a layered RPM and make sure
the firewall allows SSH connections
```

**What happens:** the brain sends the request to the planner, which
proposes a multi-step plan.

## Scene 2: The plan (15 seconds)

**Show:** the plan pane rendering each step.

**What the viewer sees:**

| Step | Action | Risk |
| --- | --- | --- |
| 1 | `rpm_ostree_install htop` | Medium |
| 2 | `firewall_add_service ssh` | High |

Each step shows:

- the typed action name (not a raw shell command)
- risk level badge (color-coded)
- preview details (what will change)
- rollback metadata (how to undo)

**Narration point:** "Every step is a typed action. You see exactly
what will change before anything runs."

## Scene 3: Approval (5 seconds)

**Action:** click the Approve button.

**Narration point:** "Nothing runs until you explicitly approve."

## Scene 4: Execution with live output (20 seconds)

**Show:** the execution timeline scrolling in real time.

**What the viewer sees:**

- Step 1 starts, live stdout lines appear as rpm-ostree downloads
  and stages the package
- Step 1 completes with a green checkmark
- Step 2 starts, firewall rule is applied
- Step 2 completes

**Narration point:** "Live output streams as each step executes.
The daemon handles all privileged operations."

## Scene 5: Rollback demo (20 seconds)

**Setup:** prepare a scenario where a High-risk action fails.
Options:

1. Temporarily make `rpm-ostree rollback` fail by stopping
   the ostree daemon (will trigger automatic rollback path)
2. Use a mock action that intentionally fails
3. Disconnect the network mid-download to trigger a timeout

**Action:** submit a request that triggers a High-risk action,
approve it, let it fail.

**What the viewer sees:**

- Step starts executing
- Step fails (red X)
- Rollback automatically triggers
- Transaction log shows the failure and rollback

**Narration point:** "When a high-risk action fails, SysKnife rolls
back automatically. Every execution is logged."

## Scene 6: Audit trail (5 seconds)

**Show:** the SQLite transaction log (via CLI or shell UI).

**Action:** show that every action, approval, and rollback is
recorded with timestamps.

## Recording notes

- **Resolution:** 1920x1080 or 1280x720
- **Font size:** 16pt minimum for readability
- **Speed:** real-time for execution, can speed up package downloads
- **Duration target:** 60-90 seconds total
- **Format:** MP4 for the full demo, GIF (15-20s loop) for the README
- **GIF content:** scenes 1-3 (request → plan → approve) — the core
  "aha moment" loop

## Post-production

1. Trim dead time (typing pauses, download waits)
2. Add captions for each scene transition
3. Export GIF from scenes 1-3 at 720p, max 5 MB
4. Place GIF at `docs/assets/demo.gif`
5. Update README to reference the GIF
