# Hacking on SysKnife

Real-world notes for getting a working SysKnife development + testing setup
on your own hardware, with all the gotchas we hit and the workarounds
that stuck. If you just want to run unit tests, see
[CONTRIBUTING.md](CONTRIBUTING.md) — `cargo nextest run --workspace` and `pnpm
test` are the only required gates for a PR.

If you want to run SysKnife end-to-end against a real Fedora Atomic Desktop
in a VM — for story validation, demo recording, or pre-release QA —
keep reading.

## TL;DR

```sh
# One-time host setup (Ubuntu 24.04 shown — adjust for your distro)
sudo add-apt-repository -y ppa:flexiondotorg/quickemu
sudo apt-get update
sudo apt-get install -y quickemu qemu-system-x86 qemu-utils \
    qemu-system-modules-spice rsync netcat-openbsd libguestfs-tools
sudo chmod +r /boot/vmlinuz-*            # required for libguestfs, see §2
test -r /dev/kvm || sudo usermod -aG kvm "$USER"   # then log out / back in

# SysKnife VM lifecycle
./tests/e2e/atomic-vm.sh keygen      # dedicated SSH key (no passphrase)
./tests/e2e/atomic-vm.sh download    # fetch Silverblue ISO (~2.7 GB)
./tests/e2e/atomic-vm.sh install     # run Anaconda — just click through
./tests/e2e/atomic-vm.sh bootstrap   # offline patch: user/passwords/sshd/key
./tests/e2e/atomic-vm.sh start       # headless boot with SSH forward
./tests/e2e/atomic-vm.sh provision   # build + install SysKnife + pull model

# Before running stories — sanity-check the whole stack in one command.
# If any line comes back [fail], fix that before burning 10 min on a story.
# See §11 for what each line means.
./tests/e2e/atomic-vm.sh ssh \
    'sudo -E SYSKNIFE_LISTEN_URI=unix:///run/sysknife/daemon.sock sysknife-test-cli --doctor'

./tests/e2e/atomic-vm.sh stop
./tests/e2e/atomic-vm.sh snapshot baseline    # snapshot before tests
./tests/e2e/atomic-vm.sh start
./tests/e2e/atomic-vm.sh run         # stories 1–7
SYSKNIFE_ALLOW_DESTRUCTIVE=1 ./tests/e2e/atomic-vm.sh run  # all 54
./tests/e2e/atomic-vm.sh stop
./tests/e2e/atomic-vm.sh restore baseline
```

**Want qwen3:8b quality without GPU passthrough?** Run Ollama on the
host with `OLLAMA_HOST=0.0.0.0:11434`, then from the guest point SysKnife
at it:

```sh
SYSKNIFE_OLLAMA_URL=http://10.0.2.2:11434 \
SYSKNIFE_LLM_MODEL=qwen3:8b \
  ./tests/e2e/atomic-vm.sh run
```

See §8 for the full story on why CPU-only qwen3 doesn't work and the
`ollama_think` config option that lets you override auto-detection.

Everything below is the _why_ behind each step — read when something
breaks.

---

## 1. Why a VM, not just unit tests

SysKnife is three programs talking over a Unix socket:

- `sysknife-brain` (LLM planner)
- `sysknife-daemon` (privileged executor)
- `sysknife-shell` (Tauri/React UI)

Unit tests cover the parsers, the safety fence, the IPC framing, the
reducer transitions — the code-shaped bugs. They do **not** cover:

- Is the daemon's systemd unit wired correctly against a real
  rpm-ostree host?
- Does `rpm-ostree install <pkg>` actually work when driven through
  the daemon's action executor?
- Do the preview/approval hashes survive a reboot?
- Does the shell render correctly against a real daemon over a real
  Unix socket?

A VM is the cheapest way to answer those questions without destroying
your workstation. SysKnife is designed to run on Fedora Atomic Desktops
(Silverblue, Kinoite, Sericea, Onyx), so the VM has to be one of those
— testing on plain Fedora Cloud doesn't exercise rpm-ostree's
deployment model.

We use [quickemu] for the VM because it automates:

- downloading the official Silverblue ISO,
- generating a working QEMU/KVM configuration,
- forwarding an SSH port from host to guest.

[quickemu]: https://github.com/quickemu-project/quickemu

## 2. Host prerequisites — the non-obvious ones

### KVM access

QEMU needs `/dev/kvm` readable by your user. On most distros this is
handled by the `kvm` group, but Ubuntu 24.04 also adds an ACL so
`test -r /dev/kvm` may already return true even if you're not in the
group. Check:

```sh
test -r /dev/kvm && echo "KVM OK" || echo "need kvm group"
```

If you need to add yourself: `sudo usermod -aG kvm "$USER"` and log out
and back in.

### quickemu version

Ubuntu 24.04's default `quickemu` package is too old — it downloads
`.ociarchive` files for Fedora Atomic editions instead of the proper
`.iso` (the fix landed in upstream PR #1503 in Nov 2024). Use the
`flexiondotorg/quickemu` PPA:

```sh
sudo add-apt-repository -y ppa:flexiondotorg/quickemu
sudo apt-get update
sudo apt-get install -y quickemu
```

On Fedora 41+ the default repo is current.

### libguestfs + the Ubuntu kernel-readable fix

`virt-customize` / `guestfish` run an in-memory "appliance" built from
your host kernel. Ubuntu 24.04 ships `/boot/vmlinuz-*` as mode `0600
root:root`, so libguestfs cannot read it as your user and fails with a
confusing `supermin exited with error status 1` error. One-time fix:

```sh
sudo chmod +r /boot/vmlinuz-*
```

You only need to do this once. Fedora / Arch / openSUSE ship kernels
world-readable by default.

## 3. The install — what Anaconda gets wrong

When you run `./tests/e2e/atomic-vm.sh install`, a QEMU window
opens with the Fedora installer (Anaconda). You're tempted to think you
need to click through User Creation + set a password.

You don't. Our workflow deliberately **patches the installed disk
offline** using `libguestfs` instead, because:

- Anaconda on Fedora 42 silently skips User Creation if you don't
  explicitly click the Done button twice after setting a weak password.
  We found this the hard way — the VM booted with no login.
- `gnome-initial-setup` (the "welcome" wizard on first graphical boot)
  crashes on Fedora 42's third-party-repo toggle screen.
- `virtio-vga-gl` (virgl) flickers and freezes on hybrid-graphics hosts
  (Intel iGPU + NVIDIA dGPU).

The quickemu conf we auto-append sets `gl="off"` to avoid the virgl
crash, but the other two problems would still block us if we relied on
the graphical first-boot.

Instead, just click through Anaconda with default answers (Partitioning
→ Done, Begin Installation, wait, close the window when you see the
"Complete!" screen). **Don't click "Reboot"** — it will re-mount the
ISO as a CD-ROM and start the installer over. Close the window
instead.

Then run `./tests/e2e/atomic-vm.sh bootstrap`, which via `guestfish`:

- Creates the `lacsdev` user (uid 1000, home `/home/lacsdev`, wheel
  group).
- Sets `lacsdev:lacsdev` and `root:sysknife` passwords (SHA-512 via
  `openssl passwd -6`).
- Adds a NOPASSWD sudoers fragment so `sudo` works without a password
  (required for the automated provisioner).
- Enables `sshd` by dropping a systemd preset symlink — **Silverblue
  ships sshd disabled by default** on its workstation-class variants.
- Installs your passphrase-less SSH key at
  `/home/lacsdev/.ssh/authorized_keys`.
- Flips SELinux to permissive — we edit `/etc/shadow` and other files
  via guestfish without the correct SELinux labels, which causes sshd
  to reject key authentication in enforcing mode. We don't test
  SELinux semantics, so permissive is fine.
- Pre-marks `gnome-initial-setup` as done so it doesn't run.

All of that happens while the VM is **stopped** — no interaction
needed, no flaky GUI timing.

## 4. Why a dedicated SSH key

Contributors' personal `~/.ssh/id_ed25519` keys are typically
passphrase-protected. Interactive `ssh` works because `ssh-agent`
caches the unlocked key, but `rsync` (via `BatchMode=yes`) cannot
prompt for a passphrase and silently falls through to password auth
that we don't allow. End result: `rsync: connection closed` that takes
twenty minutes of debugging to diagnose.

`./atomic-vm.sh keygen` generates a dedicated `~/.ssh/sysknife-vm` key
with **no passphrase**. This is safe because the key only authorizes
login to your disposable test VM.

## 5. The `/usr` is read-only, but our Makefile wrote there

Fedora Atomic Desktops keep `/usr` as a read-only overlay managed by
rpm-ostree. The SysKnife Makefile defaults write to `/usr/lib/sysusers.d/`,
`/usr/lib/tmpfiles.d/`, `/usr/lib/systemd/system/`, and
`/usr/share/polkit-1/rules.d/` — all of which fail with "Read-only
file system" on Silverblue.

Fix: every path in the Makefile is now override-able with `?=`, and
the provisioner auto-detects rpm-ostree and passes the correct `/etc`
overrides:

```sh
sudo make install \
    SYSUSERS=/etc/sysusers.d \
    TMPFILES=/etc/tmpfiles.d \
    SYSTEMD=/etc/systemd/system \
    POLKIT=/etc/polkit-1/rules.d
```

systemd looks at `/etc/systemd/system/` **first** anyway (it wins over
`/usr/lib/systemd/system/`), so this is conceptually the right place
for a locally-built package. On non-ostree systems the default
Makefile behaviour still works unchanged.

## 6. The provisioner is two-phase, on purpose

`rpm-ostree install` can't add packages to a running deployment — it
stages them into the next deployment and requires a reboot to activate.
So `tests/e2e/provision.sh` splits into:

1. **Phase 1:** `rpm-ostree install gcc gcc-c++ make openssl-devel
   pkg-config zstd` → `systemctl reboot`. (Yes, `zstd` is needed: the
   Ollama installer unpacks its tarball with `unzstd`.)
2. **Phase 2 (after reboot):** rustup install, Ollama install
   (self-healing systemd unit if the upstream installer was
   interrupted), model pull, cargo build, `make install` with `/etc/`
   overrides, start sysknife-daemon.

`./atomic-vm.sh provision` detects which phase to run via a marker
file (`/var/lib/sysknife-e2e/layered`). You'll need to run it **twice** the
first time — the script will tell you when to re-run after the
auto-reboot.

## 7. Ollama's installer is fragile

The official `curl -fsSL https://ollama.com/install.sh | sh` does
multiple things:

- Downloads `ollama-linux-amd64.tar.zst` from a CDN that can be very
  slow (30 KB/s on some networks, 10 MB/s on others).
- Unpacks it to `/usr/local/bin/ollama` (works on Silverblue — that
  path is writable).
- Tries to create a system `ollama` user + `/etc/systemd/system/
  ollama.service`. On Silverblue this can half-fail silently.
- If interrupted mid-download (e.g. you Ctrl-C because the CDN is
  stuck), you end up with a binary but no unit, no user, no way to run
  `ollama serve` as a service.

Our provisioner detects the missing unit and writes a minimal one
itself:

```ini
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
Environment=HOME=/var/lib/ollama
Environment=OLLAMA_HOST=127.0.0.1:11434
Restart=always
User=lacsdev
Group=lacsdev

[Install]
WantedBy=default.target
```

This runs Ollama as `lacsdev` with `~/.ollama` redirected to
`/var/lib/ollama`, which we pre-create with correct ownership.

## 8. Choosing a model — or, "why is the LLM so slow"

The LLM runs **inside the VM, on CPU**, unless you've set up GPU
passthrough (which is out of scope for this guide — VFIO + IOMMU is a
separate rabbit hole). Empirically, with the default 4 vCPU / 10 GB
RAM VM on a mid-range laptop (Intel i5-13th gen), Ollama averages
**≈ 1 token/sec** prompt eval and **≈ 1.5 token/sec** generation.
SysKnife's planner prompt is ~1500-2000 tokens, so **expect 2–5 minutes per
story** even with a small tool-capable model, and longer with thinking
models.

Options we've tested live on this class of hardware:

| Model | Size | Tool calling | Reality on 4 vCPU | Notes |
|---|---|---|---|---|
| `gemma3:1b` | 815 MB | **no** | fast (~3 s/msg) | Ollama returns `400: does not support tools`. Great for non-tool smoke tests, **not** SysKnife stories. |
| `gemma3:4b` | 3.3 GB | marginal | slow | Occasionally emits tool calls; not reliable. |
| `qwen2.5:3b` | 1.9 GB | yes | ~2-4 min/story | Lightest tool-capable Qwen; acceptable for dev. |
| `llama3.2:3b` | 2.0 GB | yes | ~2-4 min/story | **CPU fallback.** No thinking mode; smaller context; tool calling works. Use when you don't have a GPU reachable and don't want to override thinking. |
| **`qwen3:8b`** | **5.2 GB** | **yes** | **<60 s via host GPU** | **Default.** Most reliable tool-calling. Requires a GPU — either the host's via `SYSKNIFE_OLLAMA_URL=http://10.0.2.2:11434`, or VFIO passthrough. On CPU-only, thinking exceeds Ollama's ~120 s request timeout: set `ollama_think = false` to force-off (slow but finishes) or switch to `llama3.2:3b`. |
| `qwen3:14b` | 9.3 GB | very reliable | GPU-only | Minutes of thinking tokens per story on CPU. Host GPU via `10.0.2.2:11434` works; VFIO passthrough works; CPU does not. |

**The qwen3 thinking-mode trap — and the fix SysKnife now ships.**
Qwen3 series defaults to "thinking mode": the model emits a long
hidden reasoning trace before the real answer. On CPU this
_dominates_ latency. Ollama's `/api/chat` enforces a **~120 s
request timeout** per our live testing; qwen3:8b on 4 vCPUs cannot
finish its thinking in that budget, so Ollama returns HTTP 500 and
the plan never arrives.

SysKnife now exposes thinking mode as a first-class knob:

- `sysknife-brain` auto-detects thinking-capable models by name prefix
  (`qwen3`, `qwq`, `deepseek-r`) and sends `think: true` for those;
  everything else (llama3.2, gemma, mistral, qwen2.5) gets
  `think: false`, so they no longer return HTTP 400 "does not
  support thinking" in the planning loop. See `THINKING_MODEL_PREFIXES`
  in `crates/sysknife-brain/src/planner.rs` — that slice is the source
  of truth; add a prefix only after verifying the model + Ollama
  version accepts the field.
- You can override the decision in `~/.config/sysknife/config.toml`:

  ```toml
  [llm]
  model        = "qwen3:8b"
  ollama_think = false       # force-off — required on CPU-only hosts
  # ollama_think = true      # force-on — GPU hosts only
  # ollama_think omitted     # auto-detect from model name (default)
  ```

- The env var `SYSKNIFE_OLLAMA_THINK=true|false` has the same effect
  and overrides both the config file and auto-detection.
- The shell's SetupWizard now surfaces this as a three-way radio
  (Auto / Force on / Force off), visible only when the selected
  model supports thinking.
- The output-token budget is a named constant in the planner,
  `OLLAMA_NUM_PREDICT = 4096`, sent via `options.num_predict`
  (Rig's top-level `max_tokens` is silently ignored by Ollama — see
  the doc-comment on that constant for the full story).

**Practical matrix:**

| Your setup | What to do |
|---|---|
| CPU-only VM, any model | `SYSKNIFE_LLM_MODEL=llama3.2:3b` — recommended default |
| CPU-only VM, stuck on qwen3:8b | `SYSKNIFE_OLLAMA_THINK=false` to disable thinking — still slow, but finishes |
| Host GPU reachable from VM at `10.0.2.2:11434` | `SYSKNIFE_OLLAMA_URL=http://10.0.2.2:11434 SYSKNIFE_LLM_MODEL=qwen3:8b` — keep thinking on |
| GPU passthrough (VFIO) inside VM | `SYSKNIFE_LLM_MODEL=qwen3:8b`, defaults work |

**Pointing the VM at the host GPU.** On the default QEMU SLIRP
network, the host is reachable from the guest at `10.0.2.2`. If you
run Ollama on the host with `OLLAMA_HOST=0.0.0.0:11434`, you can
point the VM at it:

```sh
# On the host, one-time:
sudo tee /etc/systemd/system/ollama.service.d/listen.conf <<'EOF'
[Service]
Environment=OLLAMA_HOST=0.0.0.0:11434
EOF
sudo systemctl daemon-reload && sudo systemctl restart ollama
sudo firewall-cmd --add-port=11434/tcp  # if firewalld is on

# In the guest, point SysKnife at the host:
SYSKNIFE_OLLAMA_URL=http://10.0.2.2:11434 \
SYSKNIFE_LLM_MODEL=qwen3:8b \
  ./tests/e2e/atomic-vm.sh run
```

This is _far_ faster than GPU passthrough (VFIO) to set up and
covers the common case of running against your own dev-box GPU.

**Overriding the provisioner default.** `tests/e2e/provision.sh`
pulls `qwen3:8b` by default. On CPU-only hosts, override with
`SYSKNIFE_TEST_MODEL`:

```sh
SYSKNIFE_TEST_MODEL=llama3.2:3b ./tests/e2e/atomic-vm.sh provision
SYSKNIFE_TEST_MODEL=llama3.2:3b ./tests/e2e/atomic-vm.sh run
```

**Raise the per-story timeout** if you're pushing CPU inference:

```sh
SYSKNIFE_STORY_TIMEOUT=900 SYSKNIFE_LLM_MODEL=llama3.2:3b \
    ./tests/e2e/atomic-vm.sh run
```

**Performance tuning.** By default Ollama uses only `NumCPU/2`
threads. For a 4-vCPU VM that's 2 — you can bump it to 4 by dropping a
systemd drop-in:

```sh
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo tee /etc/systemd/system/ollama.service.d/override.conf <<EOF
[Service]
Environment=OLLAMA_NUM_THREADS=4
Environment=OLLAMA_KEEP_ALIVE=30m
EOF
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

The `OLLAMA_KEEP_ALIVE=30m` keeps the model loaded in RAM between
stories — otherwise ollama unloads after 5 minutes of inactivity and
you pay the 5-10 s load cost on every story.

## 9. Env vars don't magically cross SSH

This one bit us hard. When you run `./atomic-vm.sh run`, the
wrapper does:

```text
ssh lacsdev@localhost  →  sudo -E  →  bash run-stories.sh
```

SSH by default only forwards `TERM` / `LANG` / `LC_*`. Any `SYSKNIFE_*` env
var you set on the host **does not** reach the test CLI in the guest
unless we forward it explicitly. `sudo -E` alone isn't enough either —
sudoers' `env_reset` default filters unknown variables.

The fix in `cmd_run` builds a `VAR='val' ...` prefix and passes it to
sudo directly: `sudo VAR=val bash run-stories.sh`. That injects the
value into the child's env regardless of sudoers config.

Forwarded vars: `SYSKNIFE_ALLOW_DESTRUCTIVE`, `SYSKNIFE_LLM_PROVIDER`,
`SYSKNIFE_LLM_MODEL`, `SYSKNIFE_TEST_MODEL`, `SYSKNIFE_OLLAMA_URL`,
`SYSKNIFE_LISTEN_URI`, `SYSKNIFE_STORY_TIMEOUT`.

## 10. Common gotchas, in the order we hit them

1. **`quickget` edition names are capitalized**: `Silverblue`,
   `Kinoite`, `Sericea` (Sway), `Onyx` (Budgie). The script maps
   lowercase input to the correct case.
2. **`quickget` outputs to `fedora-<release>-<Edition>/`, uppercase**.
   Early versions of our script looked in the lowercase path and
   couldn't find anything.
3. **Ollama downloads `.ociarchive` instead of `.iso` on old
   quickemu.** Use the flexiondotorg PPA.
4. **gnome-initial-setup crashes on Fedora 42.** `virgl=off` and
   skipping the wizard via `bootstrap` both help.
5. **Anaconda silently skips User Creation on weak passwords.**
   Bootstrap creates the user offline instead.
6. **SELinux rejects our offline-edited `~/.ssh/authorized_keys`.**
   We set SELinux to permissive in `bootstrap`.
7. **Personal SSH keys are passphrase-protected.** `keygen` creates a
   dedicated passphrase-less key.
8. **Ollama install.sh needs `zstd`.** Layered in phase 1 of provisioner.
9. **Ollama systemd unit may be missing on Silverblue.** Self-healing
   fallback in phase 2.
10. **`make install` writes to read-only `/usr`.** Makefile paths are
    now overridable; provisioner auto-uses `/etc/` on ostree.
11. **Env vars don't cross SSH.** `cmd_run` forwards them through sudo.
12. **Qwen3's thinking mode + CPU = Ollama HTTP 500 within 2 min.** The
    `/api/chat` endpoint caps at ~120 s and `qwen3:8b` can't get past
    its thinking preamble in that budget. Either point the VM at the
    host's GPU (`SYSKNIFE_OLLAMA_URL=http://10.0.2.2:11434`), force-off
    thinking (`SYSKNIFE_OLLAMA_THINK=false`), or switch to `llama3.2:3b`
    for CPU-only runs. See §8.
13. **`gemma3:1b` / `gemma3:4b` get `400: does not support tools`
    from Ollama.** Great for non-tool smoke tests but not for SysKnife
    stories — pick a tool-capable alternative (`llama3.2:3b`,
    `qwen2.5:3b`).
14. **Ollama uses only `NumCPU / 2` threads by default.** On a 4-vCPU
    VM that's 2 — bump to 4 via a systemd drop-in (see §8). Also set
    `OLLAMA_KEEP_ALIVE=30m` so the model stays resident between
    stories.
15. **First run fills `/var/home` if you rsync the repo including
    `tests/e2e/vm/`.** That directory contains the VM's own 20 GB
    qcow2 disk image; rsyncing it into the guest loops recursively
    and hits ENOSPC. `atomic-vm.sh provision` excludes `tests/e2e/vm`,
    but if you rsync manually, remember `--exclude='tests/e2e/vm'`.
16. **`sysknife-test-cli` gets `Permission denied` on `/run/sysknife/daemon.sock`
    when invoked as `lacsdev`.** The socket is `srw-rw---- sysknife:sysknife`;
    the ordinary dev user isn't in that group. Two paths:

    ```sh
    # Option A — add yourself to the group (persists across reboots):
    sudo usermod -aG sysknife lacsdev
    # log out and back in, or in the current shell:
    exec newgrp sysknife

    # Option B — run via sudo, matching how the story harness does it:
    sudo -E sysknife-test-cli --doctor
    ```

    The story harness (`tests/e2e/run-stories.sh`) already does
    `sudo -E`, so this only bites you when you're driving
    `sysknife-test-cli` by hand.

## 11. The doctor command — your first debugging step

`sysknife-test-cli --doctor` runs a sequence of health checks and
prints one line per check. Use it **before** running any story —
five minutes of ambiguous timeouts usually resolve to a single red
line in the doctor.

```sh
SYSKNIFE_LLM_MODEL=qwen3:8b \
SYSKNIFE_OLLAMA_URL=http://10.0.2.2:11434 \
SYSKNIFE_LISTEN_URI=unix:///run/sysknife/daemon.sock \
  sudo -E sysknife-test-cli --doctor
```

A clean run:

```text
sysknife-test-cli doctor
  [ ok ]  config         provider=ollama, model=qwen3:8b
  [ ok ]  daemon         reachable at /run/sysknife/daemon.sock
  [ ok ]  ollama         reachable at http://10.0.2.2:11434
  [ ok ]  model          'qwen3:8b' is pulled
  [ ok ]  thinking       enabled (auto: model starts with 'qwen3')
  [ ok ]  num_predict    4096 (options.num_predict)

doctor: all checks green.
```

What each line actually checks, and what a red line means:

| Line | What it probes | Red means |
|---|---|---|
| `config` | `BrainConfig::from_env()` resolves with `LacsConfig` applied | Missing required API key, unknown provider, bad `max_turns` |
| `daemon` | Opens `$SYSKNIFE_LISTEN_URI`, sends a `query_state` frame, reads the reply | Socket missing (daemon not started), Permission denied (see gotcha #16), or daemon crashed |
| `ollama` | `GET {SYSKNIFE_OLLAMA_URL}/api/tags` with a 5 s timeout | URL wrong, Ollama down, firewall blocks 11434, or host's `OLLAMA_HOST=0.0.0.0` not set |
| `model` | Requested model appears in `/api/tags` | `ollama pull <model>` not yet run, or typo in the tag |
| `thinking` | Decision that `planner.rs::resolve_ollama_think` will make for this model, plus _why_ (env override vs. auto-detected prefix) | Never red — this is informational, but read it to confirm your `ollama_think` override took effect |
| `num_predict` | The `OLLAMA_NUM_PREDICT` constant baked into this binary | Never red — shown so you can confirm which binary is running |

Exit codes: `0` all green, `1` any red, `2` usage error.

The doctor is also the fastest way to confirm that an env var or
`config.toml` change actually took effect — if `thinking` shows
`(auto: ...)` but you expected `(SYSKNIFE_OLLAMA_THINK=false)`, your
override didn't reach the process.

## 12. Snapshots are your friend

First-time provisioning takes 30–60 minutes (mostly waiting for the
Ollama CDN and the Rust release build). Once the VM is provisioned and
working:

```sh
./tests/e2e/atomic-vm.sh stop
./tests/e2e/atomic-vm.sh snapshot baseline
```

Every subsequent run becomes:

```sh
./tests/e2e/atomic-vm.sh start
./tests/e2e/atomic-vm.sh run
./tests/e2e/atomic-vm.sh stop
./tests/e2e/atomic-vm.sh restore baseline
```

No more waiting on Ollama, Rust, or Anaconda. The baseline is a
qcow2 internal snapshot — no extra disk space until you diverge.

## 13. When to reach for this VM vs. just `cargo test`

| Change you're making | Good enough gate |
|---|---|
| Rust logic / parsers / reducers | `cargo nextest run --workspace` |
| React components | `pnpm test` |
| IPC wire format | `cargo nextest run --workspace` + PR with `e2e` label (CI smoke) |
| Action catalogue (new actions) | Unit tests + VM run, stories 1–7 |
| rpm-ostree / systemd integration | **VM required** |
| Packaging / Makefile / sudoers / polkit | **VM required** |
| Release candidates | **VM + manual demo recording on real hardware** |

## 14. Cleaning up

- `./tests/e2e/atomic-vm.sh destroy` removes the VM disk but keeps
  the downloaded ISO under `tests/e2e/vm/`. That directory is
  gitignored; feel free to delete it entirely when you're done.
- The dedicated VM SSH key at `~/.ssh/sysknife-vm` is harmless to leave
  around; you can `rm ~/.ssh/sysknife-vm*` if you want.

## 15. Verifying the audit trail on the VM

SysKnife writes two audit records on every safety fence activation:

- `~/.local/share/sysknife/safety-audit.jsonl` — append-only JSON lines,
  always present on any host.
- systemd journal — forwarded via the native datagram socket protocol;
  only present on systemd hosts (which Silverblue is).

To trigger a fence activation and verify both records, run this from
the guest:

```sh
# Force a rejection: intent that contains a known secret prefix.
# The planner rejects it before any LLM call.
SYSKNIFE_LISTEN_URI=unix:///run/sysknife/daemon.sock \
  sysknife "check disk sk-proj-fake-key-for-testing" 2>&1 || true

# Check the JSONL file.
tail -n 1 ~/.local/share/sysknife/safety-audit.jsonl | python3 -m json.tool

# Check journald (structured fields).
journalctl SYSKNIFE_EVENT=safety_fence_rejection --since "1 minute ago" --output verbose
```

**Enabling tamper-evident sealing.**
The journal is queryable without FSS, but entries can be modified or
deleted by root. To protect them with Forward Secure Sealing:

```sh
sudo journalctl --setup-keys
# Outputs a verification key — store it offline.

# Verify integrity at any time:
sudo journalctl --verify
```

Run `--verify` after a story run to confirm no entries were tampered
with. On a clean run the output ends with `PASS`.

This is a one-time setup step. After it's done, every subsequent
journal write (including SysKnife audit entries) is cryptographically
chained to the previous one.

## 16. See also

- [`docs/contributing/testing.md`](docs/contributing/testing.md) — the
  short reference version of this file.
- [`docs/testing/user-stories.md`](docs/testing/user-stories.md) — the
  10 stories the harness runs and their pass criteria.
- [`tests/e2e/atomic-vm.sh help`](tests/e2e/atomic-vm.sh) — the
  subcommand reference, kept in sync with the script itself.

## 17. Adding a new action

An "action" is a named operation the daemon can perform — `GetDiskUsage`,
`AddLayeredPackage`, `CreateUser`, etc. Action names are string literals
duplicated across several independent match expressions and lists. The
`action_consistency` test enforces that all registrations stay in sync,
so CI will fail loudly with a precise error message if you miss one.

Here is every file you must touch, in order:

### 1. Action module — `crates/sysknife-daemon/src/actions/<module>.rs`

Add a builder function that returns an `ActionSpec`:

```rust
pub fn my_new_action(param: &str) -> ActionSpec {
    ActionSpec {
        action_name: "MyNewAction",         // must be unique across all modules
        mechanism: command_mechanism("sudo", ["some-cmd", param]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}
```

Also add a minimal `ActionSpec` to the module's `specs()` function so
the consistency test can discover it:

```rust
pub fn specs() -> Vec<ActionSpec> {
    vec![
        // existing entries …
        my_new_action("__placeholder__"),
    ]
}
```

The placeholder value just needs to satisfy any validation the function
performs — it is never executed; it is only read for its `action_name`.

### 2. Module registration — `crates/sysknife-daemon/src/actions/mod.rs`

If you created a new file, add `pub mod my_module;`. If you extended an
existing module, no change needed here.

### 3. Executor dispatch — `crates/sysknife-daemon/src/executor.rs`

Add a match arm in `build_action_spec`:

```rust
"MyNewAction" => {
    let param = validated_safe_arg(require_str(params, "param")?, "param")?;
    Ok(my_module::my_new_action(&param))
}
```

Use the `require_str` / `require_u32` / `str_array_or_empty` helpers for
param extraction, and `validated_*` helpers from `actions::validate` for
sanitisation. Never call a privileged action with unvalidated user input.

### 4. Policy — `crates/sysknife-daemon/src/policy.rs`

Add the action name to the correct role tier in `min_role_for_action`:

```rust
// Read-only → Observer
"MyNewAction" | … => CallerRole::Observer,

// Mutating → Admin
"MyNewAction" | … => CallerRole::Admin,
```

Reads are `Observer`. Writes / destructive ops are `Admin`. When in
doubt, use `Admin`.

### 5. Brain catalogue — `crates/sysknife-brain/src/planning_tools/propose_plan.rs`

Add the name to `KNOWN_ACTIONS` (alphabetical order within its group):

```rust
pub const KNOWN_ACTIONS: &[&str] = &[
    // …
    "MyNewAction",
    // …
];
```

Also update the `params` description in the `propose_plan` tool schema
so the LLM knows the expected JSON shape. The LLM uses these examples
literally — if the key name in the schema differs from what the executor
calls `require_str(params, "key")`, the plan will fail with
`MissingParam` before any OS command runs. Keep them in sync.

### 6. Consistency test — `crates/sysknife-daemon/tests/action_consistency.rs`

If you created a new action module, add it to `all_spec_action_names`:

```rust
use sysknife_daemon::actions::my_module;
// …
for spec in my_module::specs() {
    names.insert(spec.action_name);
}
```

If you extended an existing module (e.g. `users`), no change is needed —
the module is already included.

### 7. Sudoers — `packaging/sysknife-sudoers`

If the action runs a new privileged binary under `sudo`, add a
`NOPASSWD` rule:

```text
sysknife ALL=(root) NOPASSWD: /usr/bin/my-new-tool
```

Specify the full absolute path. Wildcards (`*`) in sudoers are allowed
but expand greedily — be cautious. Re-provision the VM and confirm
`sudo my-new-tool` works from the `sysknife` user before filing the PR.

### 8. Verification

```sh
cargo nextest run --workspace --locked
```

The `action_consistency` test will fail immediately if you missed step 3,
4, or 5. Fix the error message's listed name and re-run. No VM needed
for this gate.

For actions involving real OS side-effects (new command, new file path),
run the relevant exec story or write a new Tier-2 integration test in
`crates/sysknife-daemon/tests/`.

---

## 18. Adding a new distro

SysKnife dispatches distro-specific actions (package management,
deployment lifecycle) based on the runtime distro detected in
`crates/sysknife-daemon/src/distro.rs`. Adding a new distro is a
four-file change plus optional provisioner updates.

### 1. Distro enum — `crates/sysknife-daemon/src/distro.rs`

Add a variant and update `as_str`:

```rust
pub enum Distro {
    FedoraAtomic,
    Ubuntu,
    ArchLinux,    // ← new variant
    Unknown,
}

impl Distro {
    pub fn as_str(self) -> &'static str {
        match self {
            Distro::FedoraAtomic => "Fedora Atomic",
            Distro::Ubuntu => "Ubuntu",
            Distro::ArchLinux => "Arch Linux",
            Distro::Unknown => "Unknown",
        }
    }
}
```

Update `detect()` to recognise the new `ID=` value from `/etc/os-release`:

```rust
"arch" => Distro::ArchLinux,
```

Some distros set `VARIANT_ID` in addition to `ID` (as Fedora Atomic
does for Silverblue vs. Kinoite). Parse both fields and add a `matches!`
guard if you need variant-level discrimination.

Add unit tests in the `#[cfg(test)]` block at the bottom of the file —
at minimum, one test for the `ID=` value you added and one that confirms
`Distro::ArchLinux.as_str()` returns the expected string.

### 2. Action module — `crates/sysknife-daemon/src/actions/<distro>.rs`

Create a new file (e.g. `arch.rs`) with distro-specific implementations
of every action that differs from the Fedora Atomic baseline. Actions
that are universal (service control, SSH key ops, user management) do
**not** need distro-specific variants.

Typical distro-specific actions:

| Action name            | Fedora Atomic           | Ubuntu                    | Arch                      |
|------------------------|-------------------------|---------------------------|---------------------------|
| `AddLayeredPackage`    | `rpm-ostree install`    | `apt-get install -y`      | `pacman -S --noconfirm`   |
| `RemoveLayeredPackage` | `rpm-ostree remove`     | `apt-get remove -y`       | `pacman -R --noconfirm`   |
| `UpdateSystem`         | `rpm-ostree upgrade`    | `apt-get dist-upgrade -y` | `pacman -Syu --noconfirm` |
| `GetLayeredPackages`   | `rpm-ostree status`     | `dpkg --get-selections`   | `pacman -Qe`              |
| `GetPendingUpdates`    | `rpm-ostree upgrade -C` | `apt list --upgradable`   | `checkupdates`            |

The `action_name` field on each `ActionSpec` must match the existing
catalogue name exactly — the same string the executor dispatches on.
The `reboot_required` flag should reflect reality for the distro
(Fedora Atomic: true for package changes; Ubuntu/Arch: false).

### 3. Module registration — `crates/sysknife-daemon/src/actions/mod.rs`

```rust
pub mod arch;
```

### 4. Executor dispatch — `crates/sysknife-daemon/src/executor.rs`

For every action that has a distro-specific implementation, add a distro
check inside the existing match arm. The current pattern (pre-Ubuntu
wiring) is to call the Fedora Atomic function unconditionally; once
multiple distros are live, the arm becomes a match on `distro::current()`:

```rust
use crate::distro::{self, Distro};

// In build_action_spec:
"AddLayeredPackage" => {
    let package = validated_safe_arg(require_str(params, "package")?, "package")?;
    match distro::current() {
        Distro::FedoraAtomic => Ok(layering::add_layered_package(&package)),
        Distro::Ubuntu       => Ok(layering_ubuntu::install_package(&package)),
        Distro::ArchLinux    => Ok(arch::install_package(&package)),
        Distro::Unknown      => Err(ExecutorError::UnsupportedOnDistro {
            action: "AddLayeredPackage",
            distro: distro::current().as_str(),
        }),
    }
}
```

For rpm-ostree-specific actions (`RebaseSystem`, `PinDeployment`, etc.)
that have no Ubuntu or Arch equivalent, return an `UnsupportedOnDistro`
error for the non-Fedora variants rather than silently doing nothing.

### 5. Sudoers — `packaging/sysknife-sudoers`

Add `NOPASSWD` rules for every new privileged binary the new distro's
action module calls under `sudo`. The packaging file is distro-agnostic;
add the rule unconditionally (it will simply be unused on distros where
`apt-get` doesn't exist, etc.).

### 6. Provisioner — `tests/e2e/provision.sh`

If the new distro has a different package manager for build tools (gcc,
cargo, etc.) or different installation paths, add a distro branch to
the provisioner. The provisioner currently targets Fedora Atomic only
(`rpm-ostree`). At minimum, gate the `rpm-ostree` phase on `ID=fedora`
and add an equivalent `apt-get` or `pacman` phase.

### 7. Distro detection test (`distro.rs`)

The new `detect()` arm must be covered by a unit test inside
`distro.rs` that feeds synthetic `/etc/os-release` content. No VM
needed — these tests are fast and run in `cargo nextest run --workspace`.

### 8. Distro verification

```sh
cargo nextest run --workspace --locked
```

The consistency test does **not** enforce distro dispatch (it calls
`build_action_spec` with an empty params object on the current distro),
so manual VM verification on the new distro is required before claiming
the distro is supported.
