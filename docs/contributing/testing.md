# Testing SysKnife

This guide explains how to run SysKnife tests at every level — from the fast
unit tests you run locally on every change to the VM-based end-to-end
validation before a release.

## Test pyramid

| Level | What it tests | Speed | When |
|---|---|---|---|
| Unit tests (Rust) | Individual functions, parsers, traits | <5s | Every commit, every CI run |
| Unit tests (TypeScript) | React components, reducers, IPC shims | <5s | Every commit, every CI run |
| Integration (Rust) | Daemon IPC, safety fence, policy | <10s | Every commit, every CI run |
| **Dev stories (local, no VM)** | LLM plan structure for read-only stories; runs on any Linux host | 1-3 min | After brain/prompt changes |
| CI smoke (container) | Daemon + Ollama + read-only stories in a Linux runner | 5-10 min | Opt-in (PR label `e2e` or manual trigger) |
| E2E Atomic VM | **Real Silverblue** in QEMU/KVM, full stack, all 54 stories | 15-30 min first boot; 2-3 min subsequent | Local / pre-release |
| **E2E Ubuntu VM** | **Ubuntu 24.04** cloud image, full story suite, 65/65 stories | ~15 min first boot; ~2 min subsequent | After Ubuntu action changes |
| Manual QA | Real Silverblue/Kinoite hardware, destructive actions, GUI | 30-60 min | Before releases + demo video |

No single layer is enough on its own. Use the ones that match your change.

## Running unit and integration tests (required)

These run on every CI build and must pass before merge:

```sh
# Rust
cargo fmt --all --check
cargo clippy --workspace --all-features --locked -- -D warnings
cargo nextest run --workspace --locked

# TypeScript / React
cd apps/sysknife-shell
pnpm install --frozen-lockfile
pnpm test
pnpm exec tsc --noEmit
```

## Running stories on your dev machine (no VM required)

`tests/e2e/dev-stories.sh` runs the 7 read-only user stories directly on
your workstation. It builds the daemon and test CLI, starts the daemon on
`/tmp/sysknife-daemon.sock`, runs the stories, and then stops the daemon.

**What it validates:** the LLM proposes the correct plan (right action
names, risk levels, parameters). It does **not** execute the actions — it
tests plan structure only. This works on any Linux host because the story
scripts check the JSON plan output, not the results of `df`, `ps`, etc.

**LLM provider:** auto-detected from environment variables (same logic as
the product's `BrainConfig::from_env`):

| Variable set | Provider used | Model |
|---|---|---|
| `ANTHROPIC_API_KEY` | `anthropic` | `claude-sonnet-4-6` |
| `OPENAI_API_KEY` | `openai` | `gpt-4.1` |
| `GEMINI_API_KEY` | `gemini` | `gemini-2.0-flash` |
| neither | `ollama` | `qwen3:8b` (must be pulled; CPU-only is impractical — use `SYSKNIFE_LLM_MODEL=llama3.2:3b` on CPU) |

Override with `SYSKNIFE_LLM_PROVIDER` and `SYSKNIFE_LLM_MODEL`.

```sh
# Run the default read-only stories with an Anthropic key
ANTHROPIC_API_KEY=sk-ant-... tests/e2e/dev-stories.sh

# Run with OpenAI
OPENAI_API_KEY=sk-proj-... tests/e2e/dev-stories.sh

# Run with local Ollama (must have qwen3:8b or llama3.2:3b pulled)
tests/e2e/dev-stories.sh

# Run specific stories
OPENAI_API_KEY=sk-... tests/e2e/dev-stories.sh 3 6 7

# Stories 8-10 require SYSKNIFE_ALLOW_DESTRUCTIVE=1 — they will fail on a
# non-Fedora-Atomic host because query_packages / query_authorized_keys
# call rpm-ostree and SSH tools that are not installed. This is expected.
# Run them on a provisioned VM for real coverage.
SYSKNIFE_ALLOW_DESTRUCTIVE=1 OPENAI_API_KEY=sk-... tests/e2e/dev-stories.sh
```

**When to use this tier:**

- After any change to `crates/sysknife-brain/src/prompt.rs`
- After adding or changing a `query_*` tool or `Get*`/`List*` action
- As a quick sanity check for brain/planner changes before pushing

**Expected results on a dev machine:**

- Stories 1-7: all pass
- Story 8 (install vim): fails — model calls `query_packages`, daemon
  can't run `rpm-ostree`, model escalates to `get_system_state` →
  `StateUnavailable`. Passes on a real VM where `rpm-ostree` is present.
- Story 9 (create toolbox): may pass plan-structure check (plan
  structure only, no toolbox is created).
- Story 10 (add SSH key): fails for the same reason as story 8 —
  `query_authorized_keys` fails without the SSH tooling. Passes on a
  real VM.

For full story 8 and 10 coverage, use the VM path.

## Running the CI smoke test (opt-in)

The smoke test boots Ollama and the daemon directly in a GitHub Actions
runner (no VM, no real atomic desktop), pulls a small tool-capable model
(`llama3.2:3b`), and runs the 7 read-only user stories.

**Triggers:**

1. Label a PR with `e2e` — the workflow runs automatically
2. Manual dispatch via Actions → **e2e** → Run workflow

Results appear as the `container-smoke` job. Story logs are uploaded as
build artifacts.

**What the smoke test covers:**

- Daemon startup, IPC framing, policy enforcement
- Brain ↔ Ollama integration, tool-use loop, safety fence
- All 7 read-only query tools and read-only action stories (1–7)

**What it does NOT cover** (that's the VM path below):

- rpm-ostree actions, real systemd host management
- Reboot / kernel-argument flows, rollback execution
- Tauri GUI rendering

## Running the full E2E suite in a Fedora Atomic VM

This is the **high-fidelity** path. The VM is a real Fedora Atomic Desktop
(Silverblue, Kinoite, Sway Atomic, Budgie Atomic, or COSMIC Atomic) install
with rpm-ostree, systemd, flatpak, podman, and toolbox. All 54 user stories —
including destructive ones — execute authentically.

### Linux and macOS hosts (recommended)

We use [quickemu] to download the official Fedora ISO and boot it in
QEMU/KVM with SSH forwarding pre-configured. One-time setup, then a
reproducible VM you can snapshot and restore.

[quickemu]: https://github.com/quickemu-project/quickemu

**Install quickemu:**

You also need `qemu-system-x86_64`, `qemu-utils` (for `qemu-img`), `rsync`,
`netcat`, and `ssh` — these are all standard packages on every supported
distro.

```sh
# Fedora 41+ (default repos have a current quickemu)
sudo dnf install quickemu qemu qemu-img

# Fedora Atomic Desktops
sudo rpm-ostree install quickemu qemu qemu-img
# Reboot to activate, then proceed.

# Ubuntu 24.04 / Debian — the version in default Ubuntu repos may be too
# old (missing the Nov 2024 .ociarchive fix for Fedora Atomic). Use the PPA:
sudo add-apt-repository -y ppa:flexiondotorg/quickemu
sudo apt-get update
sudo apt-get install -y quickemu qemu-system-x86 qemu-utils \
    qemu-system-modules-spice rsync netcat-openbsd

# macOS (Homebrew)
brew install --cask quickemu
```

After installing, verify your user can access KVM (Linux only):

```sh
ls -l /dev/kvm           # should exist
test -r /dev/kvm \
    || sudo usermod -aG kvm "$USER"   # then log out and back in
                                       # (or use ACL: setfacl -m u:$USER:rw /dev/kvm)
```

You also need `libguestfs-tools` for the offline disk patches we apply
between Anaconda's install and the first SSH login (set passwords,
install our SSH key, enable sshd). Ubuntu 24.04 keeps kernel images at
mode 0600 by default, which prevents libguestfs from running
unprivileged — fix once with `sudo chmod +r /boot/vmlinuz-*`.

```sh
sudo apt-get install -y libguestfs-tools
sudo chmod +r /boot/vmlinuz-*
```

**One-time VM setup:**

```sh
# From the repo root.

# 1. Generate a passphrase-less SSH key dedicated to the VM (you do
#    not want to reuse your personal id_ed25519 — rsync/non-interactive
#    ssh cannot prompt for a passphrase). Idempotent.
./tests/e2e/atomic-vm.sh keygen

# 2. Download the Silverblue 43 ISO (~2.5 GB, cached under tests/e2e/vm/).
./tests/e2e/atomic-vm.sh download

# 3. Run the Fedora installer interactively (GUI window opens).
#    Just click through it — you don't need to set a password or create
#    a user; we patch all of that into the disk image afterwards via
#    libguestfs. Shut the VM down when the installer finishes (close
#    the QEMU window or pick "Power Off" in the post-install screen —
#    DO NOT click "Reboot": the ISO will re-mount as CD-ROM).
./tests/e2e/atomic-vm.sh install

# 4. Patch the disk image with our test user, password, sudoers, sshd,
#    and SSH key. (Implemented via guestfish so it works offline,
#    bypassing Silverblue's interactive first-boot wizard which has
#    gnome-initial-setup quirks on some hosts.)
./tests/e2e/atomic-vm.sh install-key
```

> Why no `enable-ssh` step? Earlier versions of this script tried to
> boot the VM visibly so the contributor could enable sshd by hand.
> That ran into Fedora 42's gnome-initial-setup crashing on the
> third-party-repo screen with virgl/Wayland bugs. The current flow
> sidesteps the GUI entirely by configuring the VM offline via
> `libguestfs`. The `enable-ssh` subcommand is still there as a fallback
> if your Anaconda install did create a usable user.
>
> What `bootstrap` does, in one shot: create user `lacsdev`, set the
> password (`lacsdev`), set root password (`sysknife`), install your VM
> SSH key, NOPASSWD-sudoers `lacsdev`, enable `sshd`, set SELinux to
> permissive, and pre-mark `gnome-initial-setup` as done. Idempotent —
> safe to re-run after `install`.

**Run the tests:**

```sh
# Boot the VM headlessly (in the background)
./tests/e2e/atomic-vm.sh start

# First-ever provision: rsyncs the repo into the VM, layers build tools
# via rpm-ostree, reboots the VM, then runs again to build SysKnife and
# pull the Ollama model. Re-run after the auto-reboot (the script tells
# you when). Expect 30-60 minutes total on first run (mostly waiting
# for Ollama tarball + Rust deps download). ~2 minutes on subsequent
# provisions.
./tests/e2e/atomic-vm.sh provision

# RECOMMENDED: take a "baseline" snapshot now, before any test run.
# Future test runs can `restore baseline` instead of re-provisioning.
./tests/e2e/atomic-vm.sh stop
./tests/e2e/atomic-vm.sh snapshot baseline
./tests/e2e/atomic-vm.sh start

# Run the read-only stories (non-destructive default)
./tests/e2e/atomic-vm.sh run

# Run ALL 54 stories including destructive — restore the baseline afterwards.
SYSKNIFE_ALLOW_DESTRUCTIVE=1 ./tests/e2e/atomic-vm.sh run

# Roll back to the clean baseline so the next run is fast
./tests/e2e/atomic-vm.sh stop
./tests/e2e/atomic-vm.sh restore baseline
```

**Other useful commands:**

```sh
./tests/e2e/atomic-vm.sh ssh            # interactive shell in the VM
./tests/e2e/atomic-vm.sh stop           # clean shutdown
./tests/e2e/atomic-vm.sh destroy        # delete VM disk (ISO kept)
./tests/e2e/atomic-vm.sh help
```

**Try a different atomic variant:**

```sh
SYSKNIFE_VM_VARIANT=kinoite ./tests/e2e/atomic-vm.sh download
SYSKNIFE_VM_VARIANT=kinoite ./tests/e2e/atomic-vm.sh install
# ... all management commands respect SYSKNIFE_VM_VARIANT.
```

Supported variants (these are the names quickget uses):

| `SYSKNIFE_VM_VARIANT` | Atomic Desktop | Desktop |
|---|---|---|
| `silverblue` (default) | Fedora Silverblue | GNOME |
| `kinoite` | Fedora Kinoite | KDE Plasma |
| `sericea` | Fedora Sway Atomic | Sway |
| `onyx` | Fedora Budgie Atomic | Budgie |
| `cosmic-atomic` | Fedora COSMIC Atomic | COSMIC |

### Windows hosts

quickemu does not support Windows as a host. Contributors on Windows
should use WSL2 (with KVM nested virtualization) or VirtualBox with a
manual ISO install:

1. Download the Silverblue ISO from
   [fedoraproject.org/atomic-desktops/silverblue](https://fedoraproject.org/atomic-desktops/silverblue/)
2. Create a VirtualBox VM (4 GB RAM, 2 vCPUs, 20 GB disk) with SSH port
   forwarded from host 22220 → guest 22
3. Attach the ISO, boot, and run the Fedora installer. Create user
   `lacsdev`. Enable sshd during install.
4. SSH into the VM: `ssh -p 22220 lacsdev@127.0.0.1`
5. Clone the repo into `/home/lacsdev/sysknife` and run
   `sudo bash tests/e2e/provision.sh` inside the VM
6. Run stories with `sudo -E tests/e2e/run-stories.sh`

The `atomic-vm.sh` helper does not automate VirtualBox — that's a
follow-up if Windows contributor interest warrants it.

## Running the Ubuntu 24.04 E2E suite

Ubuntu 24.04 support is validated (65/65 stories pass on a live VM with
gpt-4.1). The `ubuntu-vm.sh` script mirrors the `atomic-vm.sh` workflow but
uses a Ubuntu 24.04 cloud image instead of a Fedora Atomic ISO.

See [docs/contributing/ubuntu-vm-testing.md](ubuntu-vm-testing.md) for the
full setup and daily-use instructions. Quick reference:

```sh
# One-time setup
./tests/e2e/ubuntu-vm.sh download
./tests/e2e/ubuntu-vm.sh install

# Daily use
./tests/e2e/ubuntu-vm.sh start
./tests/e2e/ubuntu-vm.sh provision
./tests/e2e/ubuntu-vm.sh run

# Snapshot / restore for fast subsequent runs
./tests/e2e/ubuntu-vm.sh stop
./tests/e2e/ubuntu-vm.sh snapshot baseline
./tests/e2e/ubuntu-vm.sh start
```

**When to use this tier:** after any change to Ubuntu-specific actions
(`AptInstall`, `AptRemove`, `UfwAllow`, …), the `render_debian_prompt`
function, or the Ubuntu story scripts.

## Running individual stories

Inside the VM (or on any provisioned Fedora Atomic Desktop):

```sh
cd /home/lacsdev/sysknife

# Run a specific story by number
sudo -E tests/e2e/run-stories.sh 3

# Run multiple specific stories
sudo -E tests/e2e/run-stories.sh 1 4 7
```

Per-story logs are written to `tests/e2e/logs/story-N.log`.

## Before opening a PR

1. `cargo nextest run --workspace && pnpm test` — required, fast
2. `cargo clippy --workspace --all-features --locked -- -D warnings`
3. `cargo fmt --all --check`
4. For changes to the brain, daemon, IPC, or action catalogue:
   - Run the VM tests locally (`atomic-vm.sh` flow)
   - Add the `e2e` label to trigger the CI smoke test on your PR

## Before a release

The maintainer runs these in order:

1. All automated tests green on main
2. VM tests (at least Silverblue + one other atomic variant) pass locally
3. Manual QA on real Silverblue hardware using
   [docs/testing/user-stories.md](../testing/user-stories.md) as the
   checklist — all 54 stories including destructive ones
4. Record the demo video on real hardware (issue #32)

## Troubleshooting

### `quickget fedora 43 silverblue` fails

Check the [quickemu wiki](https://github.com/quickemu-project/quickemu/wiki)
for current supported editions. Older or newer Silverblue releases may
also be available; adjust `SYSKNIFE_VM_RELEASE`.

### VM boots but `atomic-vm.sh ssh` times out

The Fedora installer doesn't enable sshd by default. Either enable
`sshd` during the interactive install, or boot the VM's GUI console
once to run:

```sh
sudo systemctl enable --now sshd
```

### `provision` step fails during rpm-ostree install

rpm-ostree install requires a reboot. The provision script auto-reboots
and asks you to re-run it. If it got stuck, just run `provision` again —
it's idempotent.

### Ollama download or model pull is very slow

Two distinct downloads can be slow:

1. **The Ollama tarball itself** (~1.5 GB, downloaded by `install.sh` from
   `ollama.com/download/ollama-linux-amd64.tgz`). On some networks /
   geos / times of day this CDN serves at <100 KB/s. There's no
   workaround inside the script — wait it out, or pre-stage the binary
   on the host and copy it in via SSH if you're going to re-provision
   often.

2. **The model pull** (~2 GB for the default `llama3.2:3b`, or ~5 GB
   for `qwen3:8b` if you override). Happens after Ollama is installed,
   via `ollama pull`. Goes through Ollama's registry (usually faster
   than the ollama.com CDN).

Override the model size with `SYSKNIFE_TEST_MODEL`:

```sh
SYSKNIFE_TEST_MODEL=llama3.2:3b ./tests/e2e/atomic-vm.sh provision  # default, CPU-only friendly
SYSKNIFE_TEST_MODEL=qwen2.5:3b  ./tests/e2e/atomic-vm.sh provision  # alt tool-capable 3B
SYSKNIFE_TEST_MODEL=qwen3:8b    ./tests/e2e/atomic-vm.sh provision  # GPU passthrough only
```

We default to **`llama3.2:3b`** after empirical live testing on a
CPU-only 4-vCPU / 10 GB VM: ~2 GB download, no thinking mode, tool
calling works reliably, ~2-4 min/story.

Qwen3 models (including `qwen3:8b`) default to "thinking mode" which
emits thousands of hidden reasoning tokens before the real answer. On
CPU this blows past Ollama's internal 120-second request timeout and
every `/api/chat` call fails with HTTP 500 before a plan is emitted.
`qwen3:8b` is only a viable default if you have GPU passthrough
configured. Gemma 3 (1b / 4b) is fast but Ollama currently rejects
tool calls with `400: does not support tools`.

Per-story timeout defaults to 10 minutes (`SYSKNIFE_STORY_TIMEOUT=600`) —
small tool-capable models on 4 vCPUs need that much headroom.

For the full history of what we tried and why, see
[HACKING.md](../../HACKING.md) §8.

**Tip:** once provision succeeds end-to-end, immediately `stop` the VM
and `snapshot baseline`. Then every subsequent test cycle becomes
`restore baseline → start → run`, skipping all the slow downloads.

### CPU-only inference is too slow

Stories take 10-30 seconds each instead of 1-3 seconds with GPU.
GPU passthrough to QEMU/KVM is possible but requires VFIO setup, which
is out of scope for this guide.

### Stories fail with "daemon socket not found"

Check the daemon inside the VM:

```sh
./tests/e2e/atomic-vm.sh ssh -- sudo systemctl status sysknife-daemon
./tests/e2e/atomic-vm.sh ssh -- sudo journalctl -u sysknife-daemon -n 100
```

The provision log at `/var/log/sysknife-e2e-provision.log` usually has the
root cause.

### Getting help

- Check [existing issues](https://github.com/lacs-project/sysknife/issues)
- Open a new issue with:
  - The failing story log (`tests/e2e/logs/story-N.log`)
  - The daemon journal: `sudo journalctl -u sysknife-daemon -n 200`
  - Your Fedora variant and release (from `rpm-ostree status`)
