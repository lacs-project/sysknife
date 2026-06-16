# Roadmap

This roadmap is intentionally high level. It is meant to show
contributors where the project is going and what matters next.

## Phase 1: Foundation

- ~~publish the OSS project files~~ — done
- ~~keep the spec and implementation plan current~~ — done
- ~~establish CI, linting, and repository hygiene~~ — done
- ~~keep the architecture boundary explicit~~ — done

## Phase 2: Protocol and Daemon

- ~~implement the shared protocol crate~~ — done; `sysknife-proto` and `sysknife-types`
- ~~implement the privileged daemon skeleton~~ — done; action families, policy,
  auth, preview, jobs, transactions
- ~~persist transactions and approvals~~ — done; SQLite-backed `TransactionStore`
  with full CRUD and `update_status`
- ~~generate previews and job state~~ — done; `preview_action` covers all action
  families
- ~~IPC framing~~ — done; `FramedStream` with 4-byte LE length-prefix framing
- ~~state collection~~ — done; `collect_state` via `CommandRunner` trait
- ~~action executor~~ — done; `build_action_spec` + `execute_spec` for all ~60
  actions
- ~~wire the dispatcher~~ — done; `connection_handler` with role-based auth,
  preview, execute, and live streaming
- ~~wire the accept loop~~ — done; tokio accept loop with 16-connection limit
  and graceful shutdown

## Phase 3: Core Actions

- ~~deployment and boot controls~~ — done
- ~~Flatpak app lifecycle~~ — done
- ~~toolbox workflows~~ — done
- ~~layered package management~~ — done
- ~~package repository management~~ — done
- ~~container and runtime management~~ — done
- ~~services, network, identity, and user management~~ — done

## Phase 4: Brain and Shell

- ~~implement the planner runtime~~ — done; `sysknife-brain` has Anthropic and Ollama
  providers, a tool-use loop, plan validation, and risk classification
- ~~implement the shell UI~~ — done; intent, plan, approval gate, job timeline,
  and error states wired end-to-end
- ~~wire previews~~ — done; daemon preview handler and shell preview renderer both
  complete
- ~~wire approvals, jobs, and timeline to the daemon dispatcher~~ — done;
  `approve_preview` routes through the daemon, job progress streamed live
- ~~replace `DemoStateClient` with real daemon IPC~~ — done; `DaemonIpcClient`
  with 600-second execute timeout and live progress frames
- ~~live stdout streaming~~ — done; each output line sent as a `JobProgress`
  frame as the process runs
- ~~automatic rollback~~ — done; High-risk rpm-ostree failures trigger
  `rpm-ostree rollback` automatically

## Phase 5: Release Quality

- ~~systemd unit file (`sysknife-daemon.service`) and install script~~ — done;
  sysusers.d, tmpfiles.d, polkit rules, sudoers, Makefile with
  build/install/uninstall targets
- ~~shell reconnect with exponential backoff~~ — done; background health
  poller emits `sysknife:daemon-status` events
- ~~`~/.config/sysknife/config.toml` support~~ — done; `LacsConfig` reads
  XDG-aware config and applies defaults to env vars
- ~~Tauri bundle configuration for AppImage and RPM~~ — done; Flatpak
  manifest added
- ~~CI fix~~ — done; Tauri system deps, pnpm, clippy, all three jobs green

Remaining:

- harden the test matrix (integration tests against a real daemon socket)
- stabilize the wire protocol and cut a v0.1 release
- contributor-facing demo on real hardware with rollback visible

## Phase 6: Security and Correctness

Tracked in the v0.2.0 milestone.

- ~~role-to-action allowlist in `policy.rs`~~ — done; per-action authorization
  in `min_role_for_action`
- ~~rollback execution path~~ — done; `RolledBack` state reachable, integration
  tested
- ~~structured persistent audit log~~ — done; safety fence events written to
  SQLite
- ~~`Plan::new` error handling~~ — done; returns `Result` instead of panicking
- ~~stream `job_event` frames from daemon~~ — done; live `JobProgress` frames
  during execution

- ~~`ActionName` newtype (#10)~~ — done; `PlanStep` now takes `ActionName`,
  validated at parse time
- ~~`CuratedState` private fields (#11)~~ — done; custom `Deserialize`
  enforces invariants

## Phase 7: UX Polish

Tracked in the v0.3.0 milestone. All items complete.

- ~~reconnect banner in shell chrome~~ — done
- ~~risk-scaled confirmation modal~~ — done; typed action name for High-risk
- ~~execution pane with real-time timeline and cancel button~~ — done
- ~~plan pane step breakdown with risk badges~~ — done
- ~~first-run experience / LLM provider setup wizard~~ — done
- ~~surface config errors to shell UI~~ — done

## Phase 8: Multi-distro

Tracked in the v0.4.0 milestone.

- ~~apt action family (Debian/Ubuntu 24.04)~~ — done; 65/65 stories pass on a
  live Ubuntu 24.04 VM with gpt-4.1
- ~~runtime distro detection~~ — done; `detect_distro()` reads `/etc/os-release`
- ~~per-distro prompt dispatch~~ — done; `render_fedora_prompt` /
  `render_debian_prompt` / `render_generic_prompt` (PR #203)
- ~~Ubuntu 22.04 (jammy) VM tooling~~ — done; multi-LTS ubuntu-vm.sh, smoke tests pass
- ~~Ubuntu 26.04 (resolute) VM tooling~~ — done; multi-LTS ubuntu-vm.sh, smoke tests pass
- Ubuntu 22.04 full action parity (65/65 stories)
- Ubuntu 26.04 full action parity (65/65 stories)
- dnf action family (Fedora Workstation non-atomic)
- pacman action family (Arch/Manjaro)

## Phase 9: Launch

- record demo video on real Silverblue hardware (#32)
- ~~`sysknife_plan` / `sysknife_execute` MCP tools~~ — done; stdio
  transport via `rmcp`; returns typed plan JSON with resolved commands;
  execution gated on explicit user approval
- extend MCP server with direct read-only tools — expose all ~25 Observer-level
  actions (`get_disk_usage`, `list_services`, `get_authorized_keys`, …) as
  individual MCP tools so Claude Desktop can read live system state in-context;
  mutating actions remain plan-only to preserve the approval gate
- publish `sysknife-brain` and `sysknife-types` to crates.io
- Telegram interface (`sysknife-bot`) — approve plans from your phone via
  inline buttons; the viral mechanic

## Phase 10: Ecosystem

- `sysknife audit export --json` — shareable execution history
- web dashboard for teams and fleet management
