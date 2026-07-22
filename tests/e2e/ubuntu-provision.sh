#!/usr/bin/env bash
# ubuntu-provision.sh — run inside an Ubuntu LTS E2E VM as root.
#
# Supports Ubuntu 22.04 (jammy), 24.04 (noble), and 26.04 (resolute).
# Mirrors tests/e2e/provision.sh (Fedora Atomic) but for Ubuntu:
#   - apt-get installs all action-target tools
#   - Rust via rustup
#   - Builds sysknife from the synced repo
#   - Installs sysknife + sysknife-daemon binaries
#   - Writes the systemd unit and starts sysknife-daemon
#   - Touches the ready marker /var/lib/sysknife-e2e/ready
#
# Expected to run as root inside the VM after ubuntu-vm.sh sync copies
# the repo to /home/ubuntu/sysknife.

set -euo pipefail

REPO_DIR="${REPO_DIR:-/home/ubuntu/sysknife}"
VM_USER="${VM_USER:-ubuntu}"
MARKER="/var/lib/sysknife-e2e/ready"
LOG="/var/log/sysknife-e2e-provision.log"

mkdir -p /var/lib/sysknife-e2e
rm -f "$MARKER"

# Redirect all output to both the console and the log file.
exec > >(tee -a "$LOG") 2>&1

step() {
    echo ""
    echo "================================================================"
    echo "  STEP: $1"
    echo "================================================================"
}

fail() {
    echo ""
    echo "!!! PROVISIONING FAILED at step: $1"
    echo "!!! Check $LOG for details."
    exit 1
}

# ---------------------------------------------------------------------------
# Detect Ubuntu version
# ---------------------------------------------------------------------------

# shellcheck source=/dev/null
. /etc/os-release
UBUNTU_VERSION_ID="${VERSION_ID:-unknown}"
echo "Detected Ubuntu VERSION_ID=${UBUNTU_VERSION_ID}"

case "$UBUNTU_VERSION_ID" in
  22.04) UBUNTU_CODENAME="jammy"    ;;
  24.04) UBUNTU_CODENAME="noble"    ;;
  26.04) UBUNTU_CODENAME="resolute" ;;
  *)
    echo "WARNING: Unrecognised Ubuntu version ${UBUNTU_VERSION_ID}. Proceeding with best-effort provisioning."
    UBUNTU_CODENAME="unknown"
    ;;
esac
echo "Ubuntu codename: ${UBUNTU_CODENAME}"

# ---------------------------------------------------------------------------
# Smoke-check apt — fail fast if the package manager is broken
# ---------------------------------------------------------------------------

step "Smoke-check apt"
apt-get --version || fail "apt-get --version"
# Smoke-check apt itself. Previously piped to `head -5`, which always exits 0
# (sucking SIGPIPE before pipefail can fire), so the `|| fail` branch never
# ran even when apt was completely broken. Just exercise the command and
# discard the (potentially noisy) output — exit status alone is the signal.
apt list --upgradable >/dev/null 2>&1 || fail "apt list --upgradable"
echo "apt smoke check passed."

# ---------------------------------------------------------------------------
# jammy (22.04) pre-flight: ensure software-properties-common is installed
# ---------------------------------------------------------------------------

if [ "$UBUNTU_CODENAME" = "jammy" ]; then
    step "jammy pre-flight: install software-properties-common if missing"
    if ! command -v add-apt-repository &>/dev/null; then
        echo "add-apt-repository not found — installing software-properties-common..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common \
            || fail "Install software-properties-common (jammy pre-flight)"
    else
        echo "add-apt-repository already present: $(which add-apt-repository)"
    fi
fi

# ---------------------------------------------------------------------------
# Step 1: apt-get — install all tools the action suite needs
# ---------------------------------------------------------------------------

step "Install build tools and action targets via apt-get"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y || fail "apt-get update"

# Core build deps + SSL/SQLite headers (for compiling sysknife)
apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    curl \
    wget \
    jq \
    rsync \
    netcat-openbsd \
    software-properties-common \
    || fail "Install build tools"

# Tools exercised by Ubuntu user stories.
# Install each optional tool individually and aggregate failures into a single
# end-of-step diagnostic block so they aren't buried in apt's verbose output.
# Non-fatal — story-level prechecks gate per-tool functionality.
declare -a _STORY_TOOL_FAILURES=()
for _pkg in ufw firewalld snapd distrobox netplan.io; do
    if ! apt-get install -y "$_pkg"; then
        _STORY_TOOL_FAILURES+=("$_pkg")
    fi
done
if [ ${#_STORY_TOOL_FAILURES[@]} -eq 0 ]; then
    echo "Story target tools installed: ufw firewalld snapd distrobox netplan.io"
else
    echo ""
    echo "================================================================"
    echo "  WARNING: ${#_STORY_TOOL_FAILURES[@]} optional tool(s) failed to install on ${UBUNTU_CODENAME}:"
    for _pkg in "${_STORY_TOOL_FAILURES[@]}"; do
        echo "    - $_pkg"
    done
    echo "  Stories that exercise these tools will fail at run time;"
    echo "  precheck them with 'command -v' before invocation."
    echo "================================================================"
    echo ""
fi

# ---------------------------------------------------------------------------
# Step 2: Rust via rustup (as the VM user, not root)
# ---------------------------------------------------------------------------

step "Install Rust via rustup"
if ! su - "$VM_USER" -c 'command -v cargo &>/dev/null'; then
    su - "$VM_USER" -c \
        'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable' \
        || fail "Install Rust"
fi
# Source cargo env for root too so we can run cargo in subsequent steps.
# Assert the env file actually exists — a partial rustup install (e.g. mid-
# download network failure) leaves the script otherwise reporting "Rust
# verification" failures instead of the actionable "rustup did not produce
# the env file" diagnostic.
[ -f "/home/${VM_USER}/.cargo/env" ] \
    || fail "rustup did not produce /home/${VM_USER}/.cargo/env (partial install?)"
# shellcheck source=/dev/null
source "/home/${VM_USER}/.cargo/env"
export PATH="/home/${VM_USER}/.cargo/bin:$PATH"
su - "$VM_USER" -c 'source ~/.cargo/env && cargo --version' || fail "Rust verification"

# ---------------------------------------------------------------------------
# Step 3: Build sysknife
# ---------------------------------------------------------------------------

step "Build SysKnife from $REPO_DIR"
[ -d "$REPO_DIR" ] || fail "Repo directory $REPO_DIR not found. Run 'ubuntu-vm.sh sync' first."

# Build as the VM user (rustup toolchain lives in their home).
su - "$VM_USER" -c \
    "source ~/.cargo/env && cd $REPO_DIR && cargo build --release -p sysknife-daemon -p sysknife-cli" \
    || fail "cargo build"

echo "Built binaries:"
# Drop `2>/dev/null`: when one of the two binaries is missing, the ls stderr
# diagnostic ("ls: cannot access '…/sysknife-daemon': No such file or
# directory") is the *whole point* of this check — it tells the operator
# which binary cargo failed to produce.
ls -lh \
    "${REPO_DIR}/target/release/sysknife-daemon" \
    "${REPO_DIR}/target/release/sysknife" \
    || fail "Expected binaries not found after build"

# ---------------------------------------------------------------------------
# Step 4: Install binaries to /usr/local/bin
# ---------------------------------------------------------------------------

step "Install sysknife and sysknife-daemon to /usr/local/bin"
install -m 755 "${REPO_DIR}/target/release/sysknife-daemon" /usr/local/bin/sysknife-daemon
install -m 755 "${REPO_DIR}/target/release/sysknife"        /usr/local/bin/sysknife
echo "Installed:"
ls -lh /usr/local/bin/sysknife-daemon /usr/local/bin/sysknife

# ---------------------------------------------------------------------------
# Step 5: Install side-files (sysusers, tmpfiles, polkit, sudoers, unit)
# ---------------------------------------------------------------------------
#
# We don't call `make install` here: that target depends on `build`, which
# invokes `cargo build --release --locked` as root. Rustup is installed in
# the unprivileged user's home, so the root-side cargo has no default
# toolchain and the build fails. The binaries are already installed in
# step 4 above, so we only need the rest of the install side-files.

step "Install sysknife packaging side-files (sysusers, tmpfiles, polkit, sudoers, unit)"
cd "$REPO_DIR"

SYSUSERS_DIR=/usr/lib/sysusers.d
TMPFILES_DIR=/usr/lib/tmpfiles.d
SYSTEMD_DIR=/usr/lib/systemd/system
POLKIT_DIR=/usr/share/polkit-1/rules.d
SUDOERS_DIR=/etc/sudoers.d

# System user + group.
install -Dm 644 packaging/sysknife-sysusers.conf "${SYSUSERS_DIR}/sysknife.conf" \
    || fail "Install sysknife-sysusers.conf"
systemd-sysusers "${SYSUSERS_DIR}/sysknife.conf" || fail "systemd-sysusers"

# Runtime + state dirs.
install -Dm 644 packaging/sysknife-tmpfiles.conf "${TMPFILES_DIR}/sysknife.conf" \
    || fail "Install sysknife-tmpfiles.conf"
systemd-tmpfiles --create "${TMPFILES_DIR}/sysknife.conf" || fail "systemd-tmpfiles"

# systemd unit.
install -Dm 644 packaging/sysknife-daemon.service "${SYSTEMD_DIR}/sysknife-daemon.service" \
    || fail "Install sysknife-daemon.service"
systemctl daemon-reload || fail "systemctl daemon-reload"

# polkit rules.
install -Dm 644 packaging/50-sysknife.rules "${POLKIT_DIR}/50-sysknife.rules" \
    || fail "Install 50-sysknife.rules"

# sudoers fragment (visudo validates before install).
visudo -cf packaging/sysknife-sudoers || fail "visudo validate"
install -Dm 440 packaging/sysknife-sudoers "${SUDOERS_DIR}/sysknife" \
    || fail "Install sudoers fragment"

# Privileged helper scripts — root-owned, mode 0755, not writable by sysknife.
# grub-kargs-edit: invoked by GrubSetKargs via `sudo /usr/lib/sysknife/grub-kargs-edit`.
# Replaces the previous unconstrained python3/cp/update-grub grants (HI1/HI2/HI3).
install -Dm 755 packaging/sysknife-grub-kargs-edit /usr/lib/sysknife/grub-kargs-edit \
    || fail "Install sysknife-grub-kargs-edit"
# unattended-upgrades-edit: invoked by ConfigureUnattendedUpgrades.
install -Dm 755 packaging/sysknife-unattended-upgrades-edit /usr/lib/sysknife/unattended-upgrades-edit \
    || fail "Install sysknife-unattended-upgrades-edit"
# sshd-option-edit: invoked by SetSshdOption.
install -Dm 755 packaging/sysknife-sshd-option-edit /usr/lib/sysknife/sshd-option-edit \
    || fail "Install sysknife-sshd-option-edit"
# scheduled-job-edit: invoked by CreateScheduledJob.
install -Dm 755 packaging/sysknife-scheduled-job-edit /usr/lib/sysknife/scheduled-job-edit \
    || fail "Install sysknife-scheduled-job-edit"
# sysctl-edit: invoked by SetSysctl.
install -Dm 755 packaging/sysknife-sysctl-edit /usr/lib/sysknife/sysctl-edit \
    || fail "Install sysknife-sysctl-edit"
# mount-edit: invoked by AddMount/RemoveMount/AddSwap/RemoveSwap.
install -Dm 755 packaging/sysknife-mount-edit /usr/lib/sysknife/mount-edit \
    || fail "Install sysknife-mount-edit"
# sudoers-edit: invoked by GrantSudoAccess/RevokeSudoAccess/GetSudoGrants.
install -Dm 755 packaging/sysknife-sudoers-edit /usr/lib/sysknife/sudoers-edit \
    || fail "Install sysknife-sudoers-edit"
# apt-pin-edit: invoked by SetAptPin/RemoveAptPin.
install -Dm 755 packaging/sysknife-apt-pin-edit /usr/lib/sysknife/apt-pin-edit \
    || fail "Install sysknife-apt-pin-edit"
# log-edit: invoked by ConfigureLogRotation/RemoveLogRotation + ConfigureRemoteSyslog/RemoveRemoteSyslog.
install -Dm 755 packaging/sysknife-log-edit /usr/lib/sysknife/log-edit \
    || fail "Install sysknife-log-edit"

# ---------------------------------------------------------------------------
# Step 6: Add VM user to sysknife groups
# ---------------------------------------------------------------------------

step "Add $VM_USER to sysknife groups"
# The sysknife user/groups were created by the explicit `systemd-sysusers`
# call in step 5 (this script does the install side-files inline rather
# than calling `make install` — see the rationale in step 5's comment).
usermod --append --groups sysknife,sysknife-dev,sysknife-admin "$VM_USER" \
    || fail "usermod sysknife groups"

# Sub-UID/GID ranges for rootless Podman and Distrobox.
usermod --add-subuids 100000-165535 "$VM_USER" 2>/dev/null \
    || grep -q "^${VM_USER}:" /etc/subuid \
    || echo "${VM_USER}:100000:65536" >> /etc/subuid
usermod --add-subgids 100000-165535 "$VM_USER" 2>/dev/null \
    || grep -q "^${VM_USER}:" /etc/subgid \
    || echo "${VM_USER}:100000:65536" >> /etc/subgid

# ---------------------------------------------------------------------------
# Step 7: Write and enable the sysknife-daemon systemd unit
# ---------------------------------------------------------------------------

step "Install and enable sysknife-daemon.service"
# The unit file lives in `packaging/`; install it explicitly to
# /etc/systemd/system/ so it takes precedence over /usr/lib/systemd/system/
# and survives package upgrades without mutation of /usr.
SYSTEMD_UNIT_SRC="${REPO_DIR}/packaging/sysknife-daemon.service"
if [ -f "$SYSTEMD_UNIT_SRC" ]; then
    install -m 644 "$SYSTEMD_UNIT_SRC" /etc/systemd/system/sysknife-daemon.service
else
    # Fallback: write the unit inline (should not happen — the file is
    # tracked in the repo and the rsync step copies the whole packaging/
    # tree into the VM).
    cat > /etc/systemd/system/sysknife-daemon.service <<'UNIT'
[Unit]
Description=LACS privileged daemon
Documentation=https://github.com/lacs-project/sysknife
After=network.target

[Service]
Type=simple
User=sysknife
Group=sysknife

Environment="SYSKNIFE_LISTEN_URI=unix:///run/sysknife/daemon.sock"
Environment="SYSKNIFE_DATABASE_PATH=/var/lib/sysknife/daemon.sqlite"

ExecStart=/usr/local/bin/sysknife-daemon
Restart=on-failure
RestartSec=5s

ProtectSystem=yes
ReadWritePaths=/var/lib/sysknife /run/sysknife
RuntimeDirectory=sysknife
StateDirectory=sysknife

[Install]
WantedBy=multi-user.target
UNIT
fi

systemctl daemon-reload
systemctl enable --now sysknife-daemon || fail "Start sysknife-daemon"
sleep 2
systemctl is-active sysknife-daemon    || fail "sysknife-daemon not active after start"

# ---------------------------------------------------------------------------
# Step 8: Verify daemon socket is reachable
# ---------------------------------------------------------------------------

step "Verify daemon socket"
SOCKET_PATH="/run/sysknife/daemon.sock"
for i in $(seq 1 10); do
    if [ -S "$SOCKET_PATH" ]; then
        echo "Daemon socket exists: $SOCKET_PATH"
        break
    fi
    if [ "$i" -eq 10 ]; then
        fail "Daemon socket $SOCKET_PATH not found after 10 seconds"
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# Step 9: Write ready marker
# ---------------------------------------------------------------------------

step "Write ready marker"
date --iso-8601=seconds > "$MARKER"
echo ""
echo "================================================================"
echo "  UBUNTU PROVISIONING COMPLETE"
echo "  Ready marker: $MARKER"
echo "  Run stories:  cd $REPO_DIR && sudo -E tests/e2e/run-stories.sh"
echo "================================================================"
