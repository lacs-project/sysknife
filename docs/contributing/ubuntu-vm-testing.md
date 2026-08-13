# Ubuntu LTS VM testing

This guide explains how to validate SysKnife user stories against live
Ubuntu environments using QEMU/KVM.

Supported Ubuntu LTSes:

| Release | Codename | SSH port | Live suite | Status |
|---|---|---|---|---|
| 22.04 | jammy | 2222 | 79/79 | validated |
| 24.04 | noble | 2223 | 79/79 | validated (default) |
| 26.04 | resolute | 2224 | 79/79 | validated |

Each release has a record run and a `.replay.json` twin in
`tests/evidence/story-runs/`, and `tests/release/cassette-replay-parity.test.sh`
checks every pair it finds. All three twins currently reproduce their run with
zero misses.

Do not read a single run as a verdict on a release. Which story comes back short
moves between rounds, because the failure is a provider-side rejection of a
correctly-planned call and it lands wherever the sampling puts it — 101 on
22.04, 119 on 24.04, 125 and 130 on 26.04 across successive rounds. See
[Story 101 is flaky; story 104 was fixed](#story-101-is-flaky-story-104-was-fixed).

The Ubuntu path uses `qemu-system-x86_64` directly with a cloud-init seed
ISO — no quickemu, no interactive installer, no GUI window. The base image
is an official Ubuntu cloud image; a writable qcow2 overlay sits on top so
the base image is never modified.

## Test pyramid position

| Level | Fedora path | Ubuntu path |
|---|---|---|
| Unit / integration | `cargo nextest run` | same |
| Dev stories (no VM) | `dev-stories.sh` | same |
| E2E VM | `atomic-vm.sh` + Silverblue | **`ubuntu-vm.sh`** + Ubuntu LTS |

## Host requirements

- `qemu-system-x86_64` and `qemu-utils` (`qemu-img`)
- `genisoimage` (to build the cloud-init seed ISO)
- KVM module loaded (`/dev/kvm` readable)
- `rsync`, `ssh`, `curl`, `netcat-openbsd`

```sh
sudo apt-get install -y \
    qemu-system-x86 qemu-utils genisoimage \
    rsync netcat-openbsd
# Make /dev/kvm accessible
sudo usermod -aG kvm "$USER"   # log out and back in
# or: sudo setfacl -m u:$USER:rw /dev/kvm
```

## Selecting the Ubuntu release

Set `UBUNTU_RELEASE` to the codename before calling `ubuntu-vm.sh`:

```sh
UBUNTU_RELEASE=jammy    ./tests/e2e/ubuntu-vm.sh <subcommand>   # 22.04
UBUNTU_RELEASE=noble    ./tests/e2e/ubuntu-vm.sh <subcommand>   # 24.04 (default)
UBUNTU_RELEASE=resolute ./tests/e2e/ubuntu-vm.sh <subcommand>   # 26.04
```

Omitting `UBUNTU_RELEASE` defaults to `noble` — existing scripts and CI
jobs that do not set the variable continue to work unchanged.

Each release gets its own subdirectory under `tests/e2e/ubuntu-vm/<codename>/`
and its own SSH port, so all three VMs can run simultaneously on the host.

## One-time setup per release

```sh
# From the repo root.  Replace <codename> with jammy, noble, or resolute.

# 1. Prepare the base image and overlay (downloads the cloud image on first run).
UBUNTU_RELEASE=<codename> ./tests/e2e/ubuntu-vm.sh download

# 2. Boot the VM once so cloud-init finishes first-boot provisioning
#    (installs tools, resizes rootfs, injects the SSH key).
#    The script polls SSH and returns when the VM is ready (~3-5 min).
UBUNTU_RELEASE=<codename> ./tests/e2e/ubuntu-vm.sh install
```

`download` and `install` are idempotent — safe to re-run. The first-boot
bootstrap retries transient DNS, network, apt, and dpkg-lock failures. It
returns success only after the required tools are present. On failure,
`install` prints `cloud-init status` and `cloud-final` journal diagnostics and
exits non-zero instead of leaving a partially provisioned VM marked ready.

The host-side contract check does not require QEMU:

```sh
bash tests/e2e/ubuntu-vm-bootstrap.test.sh
```

## Daily use

```sh
# Boot the VM (skips cloud-init, boots in ~15 s)
UBUNTU_RELEASE=noble ./tests/e2e/ubuntu-vm.sh start

# SSH into the guest
UBUNTU_RELEASE=noble ./tests/e2e/ubuntu-vm.sh ssh

# Rsync the repo and run the full provisioner (builds + installs sysknife)
UBUNTU_RELEASE=noble ./tests/e2e/ubuntu-vm.sh provision

# Take a baseline snapshot after first provision
UBUNTU_RELEASE=noble ./tests/e2e/ubuntu-vm.sh stop
UBUNTU_RELEASE=noble ./tests/e2e/ubuntu-vm.sh snapshot baseline
UBUNTU_RELEASE=noble ./tests/e2e/ubuntu-vm.sh start

# Run the Ubuntu story suite. `ubuntu` is the derived family set; a bare `run`
# selects the curated atomic read-only subset instead.
UBUNTU_RELEASE=noble ./tests/e2e/ubuntu-vm.sh run ubuntu

# Roll back to the clean baseline
UBUNTU_RELEASE=noble ./tests/e2e/ubuntu-vm.sh stop
UBUNTU_RELEASE=noble ./tests/e2e/ubuntu-vm.sh restore baseline
```

## Record once, replay for free

A live suite run needs an API key, costs money, is capped by the planner's own
rate limit, and does not give the same answer twice: the models used here
intermittently emit a reasoning channel instead of a tool call, which is enough
to flip a story between runs. A cassette removes all four problems by recording
every LLM call once and answering from the file afterwards.

The wrapper sits at the provider boundary, so a replay still exercises prompt
assembly, the tool-use loop, the safety fence, the ActionSpec risk substitution
and the daemon IPC. Only the network hop is served from disk.

Recording is paced. The provider ceiling that has actually stopped a run here is
**tokens** per minute, not requests: one planning call carries the whole system
prompt, ~17 kB in, against a 250 k TPM org limit — about 14 calls a minute.
Unpaced, this suite issues one roughly every three seconds and overruns, and the
stories past the line come back as provider 429s. `run-stories.sh` therefore
sleeps 4 s between stories whenever it is recording (or running with no cassette
at all), and not at all on replay. Override with `SYSKNIFE_STORY_DELAY_SECS`.

Recording is also incremental: a record run serves anything already in the
cassette from disk and pays only for the calls that miss. Adding stories to an
existing family costs the new stories, not the whole suite. What does invalidate
every entry is a change to `prompt.rs`, the tool schema, or the model.

```sh
# Record. Costs one live run; the cassette lands inside the VM.
# `ubuntu` is the whole Ubuntu story family, derived from the story files. It
# replaced `$(seq 55 104)`, a hand-typed range that stops covering the suite the
# moment story 105 is added. SYSKNIFE_RESULTS_JSON writes the machine-readable
# result every published pass rate has to derive from.
CASSETTE=tests/e2e/cassettes/ubuntu-jammy-gpt-oss-120b.json
RESULTS=tests/evidence/story-runs/ubuntu-22.04-gpt-oss-120b.json
GROQ_API_KEY=gsk-... \
SYSKNIFE_LLM_PROVIDER=groq SYSKNIFE_LLM_MODEL=openai/gpt-oss-120b \
SYSKNIFE_CASSETTE="$CASSETTE" SYSKNIFE_CASSETTE_MODE=record \
SYSKNIFE_RESULTS_JSON="$RESULTS" \
UBUNTU_RELEASE=jammy ./tests/e2e/ubuntu-vm.sh run ubuntu

# Copy it out of the guest (the suite runs as root, so read it with sudo).
# Absolute path on purpose: `ssh` lands in the login home, not the repo, so a
# relative path here `cat`s nothing and the redirection still creates the file —
# leaving a 0-byte artifact that reads as a failed run rather than a missing copy.
GUEST=/home/ubuntu/sysknife
UBUNTU_RELEASE=jammy ./tests/e2e/ubuntu-vm.sh ssh "sudo cat $GUEST/$CASSETTE" > "$CASSETTE"

# If the cassette directory did not yet exist in the guest, root created it while
# recording and `sync` will fail on it afterwards with "Permission denied". Give
# it back once:
UBUNTU_RELEASE=jammy ./tests/e2e/ubuntu-vm.sh ssh \
    "sudo chown -R ubuntu:ubuntu /home/ubuntu/sysknife/tests/e2e/cassettes"

# Replay. No network, no spend, same answer every time.
SYSKNIFE_CASSETTE="$CASSETTE" SYSKNIFE_CASSETTE_MODE=replay \
SYSKNIFE_LLM_PROVIDER=groq SYSKNIFE_LLM_MODEL=openai/gpt-oss-120b \
GROQ_API_KEY=unused-under-replay \
UBUNTU_RELEASE=jammy ./tests/e2e/ubuntu-vm.sh run ubuntu

# Copy the evidence out of the guest the same way as the cassette, then commit it:
# every published pass rate is checked against these files by
# scripts/check_evidence_claims.py, so a figure with no run behind it fails CI.
UBUNTU_RELEASE=jammy ./tests/e2e/ubuntu-vm.sh ssh "sudo cat $GUEST/$RESULTS" > "$RESULTS"
```

A key still has to be *present* under replay, because `BrainConfig::from_env`
validates one before the planner is built. Its value is never used: a replay
never calls the inner provider, and a call the cassette does not cover returns
an error rather than falling through to the network. Any placeholder works, and
using a deliberately invalid one is a good way to prove the run was hermetic.

Two rules the harness enforces so a replay cannot lie:

- **A miss fails the run.** It means the recording and the code have diverged,
  most often because `prompt.rs` changed, so the results describe neither the
  recording nor the live model. The error names the system-prompt hash when that
  is the cause, since a prompt change misses every call at once.
- **Serving nothing fails the run.** A replay that answered no calls looks
  exactly like a replay where every story passed, so `run-stories.sh` reads the
  ledger next to the cassette and requires at least one served call. The ledger
  is truncated at the start of each replay, so it never inherits an older tally.

The cassette is keyed on `(provider/model, system prompt, messages, tools,
max_tokens)`. A different model therefore misses instead of inheriting someone
else's answers, which is deliberate: a recording is evidence about the model that
produced it and nothing else. Re-record after any change to `prompt.rs`, the tool
definitions, or the model.

`SYSKNIFE_CASSETTE` set without `SYSKNIFE_CASSETTE_MODE` is an error, not a
no-op. Ignoring it would send a run meant to be hermetic to the live model, and
the only symptom would be the bill.

## Running all three VMs in parallel

All three VMs bind to different host SSH ports (2222, 2223, 2224) so they
can run at the same time. Start them in separate terminals:

```sh
# Terminal 1
UBUNTU_RELEASE=jammy    ./tests/e2e/ubuntu-vm.sh start

# Terminal 2
UBUNTU_RELEASE=noble    ./tests/e2e/ubuntu-vm.sh start

# Terminal 3
UBUNTU_RELEASE=resolute ./tests/e2e/ubuntu-vm.sh start
```

Memory note: each VM uses 4 GB RAM by default (4 × 3 = 12 GB for all three).
Ensure the host has at least 14 GB free before starting all three together.
If memory is tight, run jammy and resolute sequentially and stop each after
the smoke test passes.

## Configuration

All defaults live in `tests/e2e/ubuntu-vm.conf` and can be overridden with
environment variables:

| Variable | Default | Notes |
|---|---|---|
| `UBUNTU_RELEASE` | `noble` | Which Ubuntu LTS: jammy \| noble \| resolute |
| `UBUNTU_VM_MEM` | `4096` | Guest RAM in MB |
| `UBUNTU_VM_CPUS` | `2` | Guest vCPUs |
| `UBUNTU_VM_DISK` | `20G` | qcow2 overlay size |
| `UBUNTU_VM_SSH_PORT` | per-release | 2222 / 2223 / 2224 |
| `UBUNTU_VM_USER` | `ubuntu` | Guest username |
| `UBUNTU_VM_IMAGE_CACHE` | `~/.cache/sysknife-vms` | Base image cache |
| `UBUNTU_VM_DIR` | `tests/e2e/ubuntu-vm/<codename>` | Overlay + runtime files |

The `SYSKNIFE_VM_SSH_KEY` env var overrides the SSH key path (default:
`~/.ssh/sysknife-vm`, shared with `atomic-vm.sh`).

## Subcommand reference

```
UBUNTU_RELEASE=<codename> ./tests/e2e/ubuntu-vm.sh <subcommand> [args]

  download          Prepare base image + cloud-init seed ISO + qcow2 overlay
  install           First-boot: run cloud-init, wait for SSH (3-5 min)
  start             Boot overlay headlessly, wait for SSH (~15 s)
  stop              Graceful shutdown via SSH
  ssh [cmd]         Open a shell (or run cmd) inside the VM
  sync              Rsync the repo into /home/ubuntu/sysknife/
  provision         sync + run ubuntu-provision.sh as root
  run [N…]          Run run-stories.sh (optional: specific story numbers)
  snapshot <name>   Create a named internal qcow2 snapshot (VM stopped)
  restore  <name>   Restore a named snapshot (VM stopped)
  destroy           Delete the overlay (base image kept)
  help              Print subcommand list
```

## Running individual stories

```sh
UBUNTU_RELEASE=noble ./tests/e2e/ubuntu-vm.sh ssh
cd /home/ubuntu/sysknife
sudo -E tests/e2e/run-stories.sh 3        # story 3 only
sudo -E tests/e2e/run-stories.sh 1 4 7   # multiple stories
```

Logs land at `tests/e2e/logs/story-N.log` inside the VM.

## Differences from the Fedora Atomic (atomic-vm.sh) path

| Concern | Fedora (atomic-vm.sh) | Ubuntu (ubuntu-vm.sh) |
|---|---|---|
| Base image | Fedora Silverblue ISO | Ubuntu LTS cloud image |
| Boot tooling | quickemu | qemu-system-x86_64 direct |
| First-boot | Interactive Anaconda + guestfish offline patch | cloud-init (fully automated) |
| Package manager | rpm-ostree (layers + reboot) | apt-get (no reboot) |
| Provision phases | 2 (reboot between) | 1 |
| Firewall default | firewalld | ufw + firewalld |
| Container tooling | podman + toolbox (built in) | distrobox |

## Troubleshooting

### `download` says "partial download" and tries to re-download

The background download process may still be writing the `.tmp` file. Wait
for it to finish, or remove the `.tmp` file and re-run `download` to fetch
directly.

### `install` times out waiting for SSH

Cloud-init may have encountered an error. Boot the VM in foreground mode to
watch the console:

```sh
# Edit ubuntu-vm.sh temporarily: replace _qemu_start yes → _qemu_start no
# then re-run install.
```

Check `/var/log/cloud-init-output.log` inside the VM.

### SSH succeeds but `provision` fails at `cargo build`

Rust may not be installed yet (e.g. `rustup` failed silently). Check:

```sh
UBUNTU_RELEASE=<codename> ./tests/e2e/ubuntu-vm.sh ssh 'source ~/.cargo/env && cargo --version'
```

If missing, install manually:

```sh
UBUNTU_RELEASE=<codename> ./tests/e2e/ubuntu-vm.sh ssh \
  'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
```

### `sysknife-daemon` fails to start

Check the journal:

```sh
UBUNTU_RELEASE=<codename> ./tests/e2e/ubuntu-vm.sh ssh 'sudo journalctl -u sysknife-daemon -n 100'
```

Provision log is at `/var/log/sysknife-e2e-provision.log`.

### Port already in use

Each release uses a fixed port (2222/2223/2224). To override:

```sh
UBUNTU_RELEASE=noble UBUNTU_VM_SSH_PORT=2225 ./tests/e2e/ubuntu-vm.sh start
```

### Getting help

Open an issue with:

- The failing step log
- `UBUNTU_RELEASE=<codename> ./tests/e2e/ubuntu-vm.sh ssh 'sudo journalctl -u sysknife-daemon -n 200'`
- `lsb_release -a` from inside the VM

## Story 101 is flaky; story 104 was fixed

**Story 101 (`DistroboxList alt phrasing`) — the provider rejects the call.**
The model produces a correct plan and mis-names the function carrying it, so
Groq refuses it server-side with `code: "tool_use_failed"`. The rejected payload
contains exactly what was wanted:

```json
{"name": "json", "arguments": {"steps": [{"action_name": "ListContainers", ...}]}}
```

Measured 2 failures in 6 runs.

This is not specific to story 101 — it is a property of the model and the
phrasing, and it has since been observed on 119 (24.04) and on 125 and 130
(26.04). Any story can land on it.

Two fixes, in order, because the second only became visible once the first
worked:

1. **The retry now changes its input.** It used to re-send the identical
   `(system, messages, tools)`, and the model had locked onto the wrong tool name
   *for that exact input*, so all three attempts reproduced it — the three
   `failed_generation` payloads differed only in prose wording and all three said
   `"name": "json"`. Three API calls and ~8.6 s to fail the same way. A retry
   that does not change its input is not a retry against a formatting error, so
   `complete_with_retry` now appends a correction naming the real tools before
   re-asking.
2. **The correction is now recordable.** The cassette stored only successes, so a
   story that needed the retry recorded only the *second* call. A replay starts
   from the first, misses, and — a `CassetteMiss` carrying none of the markers
   that trigger a correction — re-sends identical bytes and misses again. That
   one gap was the entire reason all three LTS replay twins reported
   `cassette_audit.verdict` `failed`. Cassette v2 records the rejection, and a
   replay takes the same path the live run took.

So a story short on a replay is worth reading as a cassette-vintage question
first. Re-record and it goes away; if it does not, the diagnostic in the story
log names the diverging message.

**Story 104 (`Apply netplan after showing config`) — fixed, and worth reading as
a worked example.** It asked for "the network config and then apply it" and
sometimes proposed `GetNetworkStatus` (live interfaces) instead of
`NetplanGetConfig` (the saved netplan YAML). Neither action's description claimed
the phrase the user typed, so the choice fell to sampling: 39 of 40 runs chose
correctly, which is exactly the rate that fails twice in one round and then
passes every time you go looking for it.

The fix was not a keyword. The model never got the *second* step wrong — it
proposed `NetplanApply` every time — and what `NetplanApply` applies is precisely
what `NetplanGetConfig` reads, so the pairing settles the ambiguity. The two
descriptions now say live-state versus saved-config explicitly, and a selection
rule states the coherence argument. After: 20 of 20.

## Reading a run

Two rules, both learned the hard way:

- **Re-run one story alone before changing anything.** The first 24.04 recording
  came in at 46/50; re-running its four failures individually passed three of
  them (65, 66, 71), so those were transient provider errors, not a regression.
- **Do not record all three releases at once.** Groq's limit that bites is
  tokens per minute, not requests per minute — the org ceiling is 250k TPM and a
  single planning call carries the whole prompt plus the action catalogue. Three
  concurrent suites at `SYSKNIFE_MAX_RPM=120` produced HTTP 429
  `rate_limit_exceeded`, which the harness reported as two ordinary story
  failures on 22.04. Record one release at a time; replays are free and can run
  in parallel, because they serve from the cassette and never call out. One
  release racing *itself* overruns the same ceiling, which is why a record run
  paces — see "Record once, replay for free".
- **Read the story log, not just the verdict.** A failing story's log now carries
  the CLI's stderr folded in under `--- sysknife stderr ---`. It used to hold the
  story's opening `echo` and nothing else, because every story redirects stderr
  to `/tmp/sysknife-story-<n>-stderr.log` and nothing collected it — so
  diagnosing a cassette miss meant re-running the whole release with a
  hand-written `tar` of `/tmp`.
