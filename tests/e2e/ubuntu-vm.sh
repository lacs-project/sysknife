#!/usr/bin/env bash
#
# ubuntu-vm.sh — boot a real Ubuntu LTS VM for SysKnife E2E testing.
#
# Supports Ubuntu 22.04 (jammy), 24.04 (noble), and 26.04 (resolute).
# Select the release with UBUNTU_RELEASE=<codename> (default: noble).
#
# Uses qemu-system-x86_64 directly with a cloud-init seed ISO. The base
# image is an official Ubuntu cloud image; a writable qcow2 overlay is
# created on top so the base image is never modified.
#
# Subcommands:
#   download    — prepare the base image and create the writable qcow2 overlay
#   install     — boot the VM once with the cloud-init seed so it finishes
#                 first-boot provisioning; polls SSH until the VM is ready
#   start       — boot the installed overlay headlessly with SSH on the
#                 per-release port (jammy:2222, noble:2223, resolute:2224)
#   stop        — graceful shutdown via SSH
#   ssh         — open an SSH shell (or run a command) inside the VM
#   sync        — rsync the repo into the VM (no build, no provision)
#   provision   — sync + run tests/e2e/ubuntu-provision.sh inside the VM as root
#   run         — execute tests/e2e/run-stories.sh inside the VM
#   snapshot    — create a named internal qcow2 snapshot (VM must be stopped)
#   restore     — restore the VM to a named snapshot (VM must be stopped)
#   destroy     — delete the qcow2 overlay (base image is kept)
#   help        — print this help
#
# Environment:
#   UBUNTU_RELEASE         — which Ubuntu LTS: jammy | noble | resolute (default: noble)
#   UBUNTU_VM_MEM          — guest RAM in MB (default: 4096)
#   UBUNTU_VM_CPUS         — guest vCPUs (default: 2)
#   UBUNTU_VM_DISK         — overlay size (default: 20G)
#   UBUNTU_VM_SSH_PORT     — host port forwarded to guest :22 (per-release default)
#   UBUNTU_VM_USER         — guest username (default: ubuntu)
#   UBUNTU_VM_IMAGE_CACHE  — directory for the base image (default: ~/.cache/sysknife-vms)
#   UBUNTU_VM_BASE_IMAGE   — base image filename (per-release default)
#   UBUNTU_VM_DIR          — overlay + runtime files dir (per-release default)
#   UBUNTU_CLOUD_IMG_URL   — download URL for the base image (per-release default)
#
# Per-release SSH ports (for simultaneous parallel runs):
#   jammy    → 2222
#   noble    → 2223  (historical default)
#   resolute → 2224
#
# Dedicated SSH key:
#   ~/.ssh/sysknife-vm (shared with atomic-vm.sh). Generated if missing.

set -euo pipefail

# ---------------------------------------------------------------------------
# Config — source defaults then apply env overrides
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONF="${SCRIPT_DIR}/ubuntu-vm.conf"

# Source the config file for defaults; env vars override afterwards.
# shellcheck source=tests/e2e/ubuntu-vm.conf
[ -f "$CONF" ] && source "$CONF"

MEM="${UBUNTU_VM_MEM:-4096}"
CPUS="${UBUNTU_VM_CPUS:-2}"
DISK="${UBUNTU_VM_DISK:-20G}"
# SSH_PORT, BASE_IMAGE, VM_DIR, and UBUNTU_CLOUD_IMG_URL are set by the conf
# case statement; honour explicit env overrides if provided.
SSH_PORT="${UBUNTU_VM_SSH_PORT}"
VM_USER="${UBUNTU_VM_USER:-ubuntu}"
IMAGE_CACHE="${UBUNTU_VM_IMAGE_CACHE:-$HOME/.cache/sysknife-vms}"
BASE_IMAGE="${UBUNTU_VM_BASE_IMAGE}"
VM_DIR="${UBUNTU_VM_DIR}"

# Resolve relative VM_DIR against repo root.
case "$VM_DIR" in
    /*) : ;;
    *)  VM_DIR="${REPO_ROOT}/${VM_DIR}" ;;
esac

BASE_IMG_PATH="${IMAGE_CACHE}/${BASE_IMAGE}"
OVERLAY="${VM_DIR}/overlay.qcow2"
SEED="${VM_DIR}/seed.iso"
PID_FILE="${VM_DIR}/vm.pid"
CLOUD_INIT_DIR="${VM_DIR}/cloud-init"

# ---------------------------------------------------------------------------
# Legacy noble migration shim
# ---------------------------------------------------------------------------
# Prior to the multi-LTS refactor, noble used tests/e2e/ubuntu-vm/ with
# different filenames (ubuntu-overlay.qcow2, ubuntu-vm.pid).  When running
# Dedicated passphrase-less SSH key for the VM. Shared with atomic-vm.sh.
SSH_KEY="${SYSKNIFE_VM_SSH_KEY:-$HOME/.ssh/sysknife-vm}"

# Approximate minimum size check for cloud images. All Ubuntu LTS cloud images
# are at least 300 MB; 314572800 = 300 * 1024 * 1024.
# The original noble check used 550 MB but jammy images are smaller (~450 MB).
# 300 MB is safe for all three releases.
_MIN_IMAGE_SIZE=314572800

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
#
# Defined BEFORE the legacy-noble migration shim below so that calling `log`
# at module-load time does not abort with `log: command not found` under
# `set -euo pipefail`.

log()  { printf '[ubuntu-vm:%s] %s\n' "$UBUNTU_RELEASE" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }

# ---------------------------------------------------------------------------
# Legacy-noble migration shim (now uses log/die above)
# ---------------------------------------------------------------------------
# When run as noble and the per-release directory does not yet exist but the
# legacy path does, emit a one-time migration notice. The user must either:
#   a) run 'download' to create a fresh noble overlay in the new location, or
#   b) manually move the files:
#        mv tests/e2e/ubuntu-vm/ubuntu-overlay.qcow2 tests/e2e/ubuntu-vm/noble/overlay.qcow2
#        mv tests/e2e/ubuntu-vm/seed.iso             tests/e2e/ubuntu-vm/noble/seed.iso
# Noble VMs provisioned before this change are unaffected until merge.
if [ "$UBUNTU_RELEASE" = "noble" ] && [ ! -d "$VM_DIR" ]; then
    _LEGACY_DIR="${REPO_ROOT}/tests/e2e/ubuntu-vm"
    if [ -f "${_LEGACY_DIR}/ubuntu-overlay.qcow2" ]; then
        log "MIGRATION NOTICE: Noble VM files found at legacy path ${_LEGACY_DIR}."
        log "  New path: ${VM_DIR}/"
        log "  To migrate, run:"
        log "    mkdir -p '${VM_DIR}'"
        log "    mv '${_LEGACY_DIR}/ubuntu-overlay.qcow2' '${VM_DIR}/overlay.qcow2'"
        log "    mv '${_LEGACY_DIR}/seed.iso'             '${VM_DIR}/seed.iso'"
        log "  Or run '$0 download' to create a fresh noble overlay."
    fi
fi

require_tools() {
    local missing=()
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        die "missing required tools: ${missing[*]}. See docs/contributing/ubuntu-vm-testing.md for install instructions."
    fi
}

ssh_opts() {
    printf -- '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i %s -o IdentitiesOnly=yes -o BatchMode=yes' "$SSH_KEY"
}

# Wait for the SSH port to accept connections (TCP probe).
wait_for_tcp() {
    local port="$1" max_wait="${2:-180}" waited=0
    log "Waiting for TCP port $port (up to ${max_wait}s)..."
    while ! nc -z -w2 127.0.0.1 "$port" 2>/dev/null; do
        if [ "$waited" -ge "$max_wait" ]; then
            die "Port $port did not open within ${max_wait}s."
        fi
        sleep 3
        waited=$((waited + 3))
    done
    log "Port $port is open."
}

# Wait until SSH key auth succeeds (not just TCP open — sshd may still be
# starting up).
wait_for_ssh_auth() {
    local port="$1" max_wait="${2:-240}" waited=0
    log "Waiting for SSH key auth on port $port (up to ${max_wait}s)..."
    # shellcheck disable=SC2046
    while ! ssh $(ssh_opts) -o ConnectTimeout=5 -p "$port" \
            "${VM_USER}@127.0.0.1" true 2>/dev/null; do
        if [ "$waited" -ge "$max_wait" ]; then
            die "SSH key auth did not succeed on port $port within ${max_wait}s."
        fi
        sleep 5
        waited=$((waited + 5))
    done
    log "SSH key auth OK on port $port."
}

# Ensure the SSH key exists (generate if missing). Idempotent.
ensure_ssh_key() {
    if [ ! -f "$SSH_KEY" ]; then
        log "Generating dedicated VM SSH key at $SSH_KEY (no passphrase)..."
        mkdir -p "$(dirname "$SSH_KEY")"
        ssh-keygen -t ed25519 -N '' -C 'sysknife-e2e-ubuntu-vm' -f "$SSH_KEY"
        chmod 600 "$SSH_KEY"
    fi
}

is_vm_running() {
    [ -f "$PID_FILE" ] || return 1
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    # Reject empty / non-numeric / non-positive PIDs. A corrupt PID file
    # would otherwise silently report "not running" and the next start
    # races a still-live QEMU on the same port.
    case "$pid" in
        '' | *[!0-9]* | 0)
            log "WARNING: PID file ${PID_FILE} contains invalid value '${pid}' — treating VM as not running"
            return 1
            ;;
    esac
    kill -0 "$pid" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_download() {
    require_tools qemu-img genisoimage
    ensure_ssh_key

    mkdir -p "$VM_DIR" "$IMAGE_CACHE" "$CLOUD_INIT_DIR"

    # --- Ensure the base image is present ---
    if [ ! -f "$BASE_IMG_PATH" ]; then
        # Check for a partial download that a background process may have
        # finished or may still be writing.
        if [ -f "${BASE_IMG_PATH}.tmp" ]; then
            local tmpsize
            # Drop `2>/dev/null || echo 0`: a stat failure (permission denied,
            # AppArmor) used to silently treat the partial download as size-0
            # and trigger a re-download. Surface the error so the operator can
            # see why stat failed.
            tmpsize=$(stat -c%s "${BASE_IMG_PATH}.tmp")
            if [ "$tmpsize" -gt "$_MIN_IMAGE_SIZE" ]; then
                log "Renaming completed download ${BASE_IMG_PATH}.tmp → ${BASE_IMG_PATH}"
                mv "${BASE_IMG_PATH}.tmp" "$BASE_IMG_PATH"
            else
                log "Base image not ready (partial at ${tmpsize} bytes). Downloading..."
                curl -fL --progress-bar \
                    -o "$BASE_IMG_PATH" \
                    "$UBUNTU_CLOUD_IMG_URL" \
                    || die "Download failed: $UBUNTU_CLOUD_IMG_URL"
                rm -f "${BASE_IMG_PATH}.tmp"
            fi
        else
            log "Downloading Ubuntu ${UBUNTU_RELEASE} cloud image..."
            curl -fL --progress-bar \
                -o "$BASE_IMG_PATH" \
                "$UBUNTU_CLOUD_IMG_URL" \
                || die "Download failed: $UBUNTU_CLOUD_IMG_URL"
        fi
    else
        log "Base image already present: $BASE_IMG_PATH"
    fi

    # --- Create (or recreate) the writable overlay ---
    if [ -f "$OVERLAY" ]; then
        log "Overlay already exists at $OVERLAY. Delete it first with 'destroy' if you want a fresh VM."
    else
        log "Creating ${DISK} qcow2 overlay on top of base image..."
        qemu-img create -f qcow2 \
            -b "$BASE_IMG_PATH" \
            -F qcow2 \
            "$OVERLAY" \
            "$DISK"
        log "Overlay created: $OVERLAY"
    fi

    # --- Build cloud-init seed ISO ---
    _build_seed_iso

    log "Download complete. Run: $0 install"
}

# Build the cloud-init seed ISO (NoCloud data source).
_build_seed_iso() {
    # Validate the public key is non-empty BEFORE we write user-data with an
    # empty ssh_authorized_keys entry — cloud-init does not error on an empty
    # key list, the VM simply boots without SSH access, and the operator only
    # discovers it 240 s later when wait_for_ssh_auth times out.
    [ -s "${SSH_KEY}.pub" ] || die "Public key ${SSH_KEY}.pub is missing or empty. Run '$0 keygen' or set SYSKNIFE_VM_SSH_KEY."
    local pubkey
    pubkey="$(cat "${SSH_KEY}.pub")"

    mkdir -p "$CLOUD_INIT_DIR"

    # meta-data is mandatory; instance-id prevents cloud-init from running
    # more than once per boot even if we reuse the same overlay.
    cat > "${CLOUD_INIT_DIR}/meta-data" <<EOF
instance-id: sysknife-ubuntu-e2e-${UBUNTU_RELEASE}
local-hostname: sysknife-ubuntu-${UBUNTU_RELEASE}
EOF

    # user-data configures the 'ubuntu' user with our SSH key and does an
    # initial apt install + rootfs resize on first boot.
    #
    # software-properties-common provides add-apt-repository.  It is not
    # pre-installed in the jammy (22.04) cloud image, so install it
    # explicitly — it is a no-op on noble/resolute where it is already present.
    cat > "${CLOUD_INIT_DIR}/user-data" <<EOF
#cloud-config
users:
  - name: ubuntu
    groups: [sudo, adm]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${pubkey}

# Grow the root partition to fill the virtual disk on first boot.
growpart:
  mode: auto
  devices: ['/']

resize_rootfs: true

# Install build essentials and tools required by the ubuntu action suite.
# This runs once on first boot; it may take a couple of minutes.
runcmd:
  - mkdir -p /var/lib/sysknife-e2e
  - apt-get update -y
  - DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config libssl-dev libsqlite3-dev curl wget jq rsync netcat-openbsd software-properties-common ufw firewalld snapd distrobox netplan.io
  - if systemctl list-unit-files --quiet | grep -q '^firewalld'; then systemctl disable --now firewalld; fi
  - echo "cloud-init first-boot complete" > /var/lib/sysknife-e2e/cloud-init-done

final_message: |
  Ubuntu ${UBUNTU_RELEASE} cloud-init setup finished.
  uptime: \$UPTIME seconds
EOF

    log "Building cloud-init seed ISO: $SEED"
    genisoimage \
        -output "$SEED" \
        -volid cidata \
        -joliet \
        -rock \
        "${CLOUD_INIT_DIR}/user-data" \
        "${CLOUD_INIT_DIR}/meta-data"
    log "Seed ISO ready: $SEED"
}

_qemu_start() {
    local daemonize="${1:-yes}"
    require_tools qemu-system-x86_64

    [ -f "$OVERLAY" ] || die "Overlay not found at $OVERLAY. Run: $0 download"
    [ -f "$SEED"    ] || die "Seed ISO not found at $SEED. Run: $0 download"

    local extra_args=()
    if [ "$daemonize" = "yes" ]; then
        extra_args+=(-daemonize -pidfile "$PID_FILE")
    fi

    # Start QEMU. Cloud-init reads the seed drive on the first boot and
    # configures the 'ubuntu' user + SSH key. Subsequent boots skip cloud-init
    # (the instance-id is already recorded in the overlay).
    # When daemonizing we must use -display none instead of -nographic.
    # -nographic conflicts with -daemonize (QEMU rejects the combination).
    local display_args=()
    if [ "$daemonize" = "yes" ]; then
        display_args=(-display none)
    else
        display_args=(-nographic -serial mon:stdio)
    fi

    qemu-system-x86_64 \
        -enable-kvm \
        -m "$MEM" \
        -smp "$CPUS" \
        -drive "file=${OVERLAY},if=virtio,format=qcow2" \
        -drive "file=${SEED},if=virtio,format=raw,readonly=on" \
        -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22" \
        -device virtio-net-pci,netdev=net0 \
        "${display_args[@]}" \
        "${extra_args[@]}"
}

cmd_install() {
    require_tools qemu-system-x86_64 nc ssh
    [ -f "$OVERLAY" ] || die "Overlay not found. Run: $0 download first."
    [ -f "$SEED"    ] || die "Seed ISO not found. Run: $0 download first."
    [ -f "$SSH_KEY" ] || die "SSH key not found. Run: $0 download first (it generates the key)."

    if is_vm_running; then
        die "VM is already running (PID=$(cat "$PID_FILE")). Stop it first: $0 stop"
    fi

    log "Booting VM for first-boot cloud-init provisioning (daemonized)..."
    _qemu_start yes

    # cloud-init runcmd installs packages (~2-3 min) then sshd becomes
    # available. Wait for TCP first, then for key auth.
    wait_for_tcp "$SSH_PORT" 60
    wait_for_ssh_auth "$SSH_PORT" 300

    log "VM is up and SSH key auth works."
    log "Waiting for cloud-init runcmd to finish (apt-get install, ~2-3 min)..."

    # Poll for the sentinel written at the end of runcmd.
    local waited=0
    local max_wait=300
    # shellcheck disable=SC2046
    while ! ssh $(ssh_opts) -p "$SSH_PORT" "${VM_USER}@127.0.0.1" \
            'test -f /var/lib/sysknife-e2e/cloud-init-done' 2>/dev/null; do
        if [ "$waited" -ge "$max_wait" ]; then
            log "WARNING: cloud-init sentinel not found within ${max_wait}s."
            log "The VM is reachable — cloud-init may still be running. Check with:"
            log "  $0 ssh 'sudo cloud-init status --long'"
            break
        fi
        sleep 10
        waited=$((waited + 10))
        log "  still waiting... ${waited}s / ${max_wait}s"
    done

    log ""
    log "Install complete. The VM is running with SSH on localhost:${SSH_PORT}."
    log "Next steps:"
    log "  $0 ssh    — verify the guest"
    log "  $0 stop   — shut down"
    log "  $0 start  — boot again headlessly"
}

cmd_start() {
    require_tools qemu-system-x86_64 nc ssh
    [ -f "$OVERLAY" ] || die "Overlay not found. Run: $0 download && $0 install"
    [ -f "$SSH_KEY" ] || die "SSH key not found at $SSH_KEY."

    if is_vm_running; then
        log "VM is already running (PID=$(cat "$PID_FILE"))."
        return 0
    fi

    log "Booting VM headlessly (SSH on localhost:${SSH_PORT})..."
    _qemu_start yes
    wait_for_tcp "$SSH_PORT" 60
    wait_for_ssh_auth "$SSH_PORT" 120
    log "VM is up. SSH: $0 ssh"
}

cmd_ssh() {
    [ -f "$SSH_KEY" ] || die "SSH key not found at $SSH_KEY."
    # shellcheck disable=SC2046
    exec ssh $(ssh_opts) -p "$SSH_PORT" "${VM_USER}@127.0.0.1" "$@"
}

cmd_sync() {
    require_tools rsync
    [ -f "$SSH_KEY" ] || die "SSH key not found. Run '$0 download' first."
    log "Syncing repo to VM..."
    rsync -az \
        --exclude=target \
        --exclude=node_modules \
        --exclude=.git/objects/pack \
        --exclude=tests/e2e/ubuntu-vm \
        --exclude=tests/e2e/vm \
        -e "ssh $(ssh_opts) -p ${SSH_PORT}" \
        "${REPO_ROOT}/" \
        "${VM_USER}@127.0.0.1:/home/${VM_USER}/sysknife/"
    log "Sync complete."
}

cmd_provision() {
    require_tools rsync
    [ -f "$SSH_KEY" ] || die "SSH key not found. Run '$0 download' first."
    cmd_sync
    log "Running ubuntu-provision.sh inside the VM as root..."
    local prov_env=""
    for var in OPENAI_API_KEY ANTHROPIC_API_KEY GEMINI_API_KEY \
               SYSKNIFE_SKIP_OLLAMA SYSKNIFE_TEST_MODEL; do
        eval "val=\${$var:-}"
        if [ -n "$val" ]; then
            prov_env+=" $var='$val'"
        fi
    done
    # shellcheck disable=SC2029
    cmd_ssh "cd /home/${VM_USER}/sysknife && sudo${prov_env} bash tests/e2e/ubuntu-provision.sh"
}

cmd_run() {
    [ -f "$SSH_KEY" ] || die "SSH key not found."
    local sudo_env=""
    for var in SYSKNIFE_ALLOW_DESTRUCTIVE SYSKNIFE_LLM_PROVIDER SYSKNIFE_LLM_MODEL \
               SYSKNIFE_TEST_MODEL SYSKNIFE_OLLAMA_URL SYSKNIFE_LISTEN_URI \
               SYSKNIFE_STORY_TIMEOUT \
               OPENAI_API_KEY ANTHROPIC_API_KEY GEMINI_API_KEY; do
        eval "val=\${$var:-}"
        if [ -n "$val" ]; then
            sudo_env+=" $var='$val'"
        fi
    done
    local story_args=""
    if [ $# -gt 0 ]; then
        story_args=" $*"
    fi
    cmd_ssh "cd /home/${VM_USER}/sysknife && sudo${sudo_env} bash tests/e2e/run-stories.sh${story_args}"
}

cmd_stop() {
    if ! is_vm_running; then
        log "VM does not appear to be running."
        return 0
    fi
    log "Requesting clean shutdown..."
    # Capture the SSH exit status instead of swallowing it. Three real
    # errors used to be silently `|| true`'d into nothing: SSH key auth
    # failure, sudo denial, systemctl-poweroff failure. Now they surface.
    local ssh_rc=0
    # shellcheck disable=SC2046
    ssh $(ssh_opts) -p "$SSH_PORT" "${VM_USER}@127.0.0.1" \
        'sudo systemctl poweroff' || ssh_rc=$?
    if [ "$ssh_rc" -ne 0 ]; then
        log "WARNING: SSH poweroff command exited with status ${ssh_rc}. The VM may still be running."
    fi
    # Wait for the TCP port to close.
    local waited=0
    while nc -z -w2 127.0.0.1 "$SSH_PORT" 2>/dev/null; do
        if [ "$waited" -ge 60 ]; then
            log "VM did not shut down within 60s. Kill the QEMU process manually:"
            log "  kill $(cat "$PID_FILE" 2>/dev/null || echo '<PID>')"
            break
        fi
        sleep 2
        waited=$((waited + 2))
    done
    # Only remove the PID file if the QEMU process is actually gone — leaving
    # a stale PID file when the VM is still alive corrupts is_vm_running()
    # for subsequent commands and causes port-in-use errors at next start.
    if is_vm_running; then
        log "QEMU process is still alive; keeping PID file at ${PID_FILE} for recovery."
    else
        rm -f "$PID_FILE"
    fi
    log "VM stopped."
}

cmd_destroy() {
    if is_vm_running; then
        die "VM is running. Stop it first: $0 stop"
    fi
    [ -f "$OVERLAY" ] || die "Overlay not found at $OVERLAY. Nothing to destroy."
    log "Removing overlay (base image is preserved)..."
    rm -f "$OVERLAY" "$SEED" "$PID_FILE"
    rm -rf "$CLOUD_INIT_DIR"
    log "Destroyed. Run '$0 download' to create a fresh overlay."
}

cmd_snapshot() {
    require_tools qemu-img
    local name="${1:-pre-destructive}"
    [ -f "$OVERLAY" ] || die "Overlay not found at $OVERLAY."
    if is_vm_running; then
        die "VM must be stopped before taking a snapshot. Run: $0 stop"
    fi
    log "Creating qcow2 snapshot '$name'..."
    qemu-img snapshot -c "$name" "$OVERLAY"
    log "Snapshot '$name' created."
}

cmd_restore() {
    require_tools qemu-img
    local name="${1:-pre-destructive}"
    [ -f "$OVERLAY" ] || die "Overlay not found at $OVERLAY."
    if is_vm_running; then
        die "VM must be stopped before restoring a snapshot. Run: $0 stop"
    fi
    log "Restoring snapshot '$name'..."
    qemu-img snapshot -a "$name" "$OVERLAY"
    log "Restored. Start the VM: $0 start"
}

cmd_help() {
    sed -n '3,/^set -euo pipefail$/p' "$0" \
        | sed -e 's/^# \?//' -e '/^set -euo pipefail$/d' -e '/^$/d'
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

cmd="${1:-help}"
shift || true

case "$cmd" in
    download)       cmd_download "$@" ;;
    install)        cmd_install "$@" ;;
    start)          cmd_start "$@" ;;
    stop)           cmd_stop "$@" ;;
    ssh)            cmd_ssh "$@" ;;
    sync)           cmd_sync "$@" ;;
    provision)      cmd_provision "$@" ;;
    run)            cmd_run "$@" ;;
    snapshot)       cmd_snapshot "$@" ;;
    restore)        cmd_restore "$@" ;;
    destroy)        cmd_destroy "$@" ;;
    help|--help|-h) cmd_help ;;
    *)              die "unknown command: $cmd. Try: $0 help" ;;
esac
