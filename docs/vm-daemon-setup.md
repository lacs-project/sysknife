# VM + Daemon Setup

This guide walks through running the SysKnife daemon inside a virtual machine
and connecting Claude Code (or any MCP client) to it from the host.

Two transport options are covered:

| Transport | Best for | Requirement |
|-----------|----------|-------------|
| **SSH socket tunnel** | Any VM, any hypervisor | SSH access to the guest |
| **virtio-vsock** | KVM/QEMU guests on the same host | `vhost_vsock` kernel module |

Both transports produce the same `.mcp.json` — only the `SYSKNIFE_SOCKET` value
and the optional `SYSKNIFE_TOKEN` differ.

---

## 1. Install and start the daemon in the VM

SSH into the guest and run:

```sh
# Clone the repo (or copy a pre-built binary)
git clone https://github.com/lacs-project/sysknife
cd sysknife

# Build and install (requires Rust stable)
make build
sudo make install

# Enable and start the daemon
sudo systemctl enable --now sysknife-daemon

# Confirm it is running
systemctl status sysknife-daemon
```

The daemon listens on `/run/sysknife/daemon.sock` by default when managed by
systemd. You can verify the socket exists:

```sh
ls -la /run/sysknife/daemon.sock
```

> **Silverblue / Kinoite (rpm-ostree hosts):** `make install` uses the correct
> rpm-ostree override flags automatically. No extra steps needed.

---

## 2a. SSH socket tunnel (simplest)

This approach works on any Linux VM regardless of hypervisor. It forwards the
daemon's Unix socket to a local path on your host.

### On the host — open the tunnel

```sh
# Replace <user>, <vm-host-or-ip>, and <port> for your setup.
# QEMU user-mode networking typically maps port 22 → 2222 on localhost.
ssh -fN \
  -L /tmp/sysknife-vm.sock:/run/sysknife/daemon.sock \
  -p 2222 <user>@localhost
```

For a network-accessible VM (libvirt bridge, cloud VM):

```sh
ssh -fN \
  -L /tmp/sysknife-vm.sock:/run/sysknife/daemon.sock \
  <user>@<vm-ip>
```

> `-fN` forks the SSH process and keeps the tunnel open without running a
> remote command. The local socket `/tmp/sysknife-vm.sock` is created on the
> host and forwards transparently to the daemon inside the guest.

### Configure and connect (SSH tunnel)

Run the setup wizard on the host and choose the integration you want:

```sh
npx sysknife-setup
```

Use `--claude`, `--cursor`, `--codex`, or `--all` if you want a direct
path without the picker.

When prompted for the daemon socket, enter `/tmp/sysknife-vm.sock`.

Or set `SYSKNIFE_SOCKET` manually in `.mcp.json`:

```json
{
  "mcpServers": {
    "sysknife": {
      "command": "/path/to/sysknife",
      "args": ["mcp-server"],
      "env": {
        "SYSKNIFE_SOCKET": "/tmp/sysknife-vm.sock",
        "SYSKNIFE_LLM_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "<your-api-key>"
      }
    }
  }
}
```

### Test the SSH tunnel connection

```sh
sysknife --dry-run "check disk usage"
```

---

## 2b. virtio-vsock (faster, no SSH required)

virtio-vsock is a kernel-level channel between the host and KVM/QEMU guests.
It requires no network stack and survives network changes inside the guest.

### Prerequisites

```sh
# On the host — load the vhost_vsock module
sudo modprobe vhost_vsock
lsmod | grep vhost_vsock   # confirm it loaded

# Persist across reboots
echo vhost_vsock | sudo tee /etc/modules-load.d/vhost_vsock.conf
```

Your VM must be started with a vsock device. With **libvirt** add this to
the domain XML:

```xml
<devices>
  <vsock model='virtio'>
    <cid auto='yes'/>
  </vsock>
</devices>
```

With **QEMU directly**:

```sh
qemu-system-x86_64 \
  ... \
  -device vhost-vsock-pci,guest-cid=10
```

### Find the guest CID

The Context ID (CID) is the vsock address of the guest. It is assigned by the
hypervisor and visible in two ways:

**From the host (libvirt):**

```sh
virsh dominfo <vm-name> | grep -i cid
# or
virsh dumpxml <vm-name> | grep cid
```

**From inside the guest:**

```sh
cat /sys/class/vsock/local_cid   # e.g. prints "10"
```

### Generate and distribute the pre-shared token

vsock connections require a pre-shared token to authenticate the host to the
daemon. This prevents other processes on the host from connecting.

```sh
# On the host — generate a token
openssl rand -hex 32
# e.g.: a3f8c2d1e4b7a0f9...

# On the guest — write the token to the daemon's token file
sudo mkdir -p /etc/sysknife
echo "admin:a3f8c2d1e4b7a0f9..." | sudo tee /etc/sysknife/token
sudo chmod 600 /etc/sysknife/token
sudo chown root:root /etc/sysknife/token

# Restart the daemon to pick up the token
sudo systemctl restart sysknife-daemon
```

The token file format is `<role>:<hex-token>` on each line:

```text
# /etc/sysknife/token
admin:<paste-token-here>
```

### Configure and connect (vsock)

Run the setup wizard on the host and choose the integration you want:

```sh
npx sysknife-setup
```

Use `--claude`, `--cursor`, `--codex`, or `--all` if you want a direct
path without the picker.

When prompted for the daemon socket, enter `vsock://<CID>:9734` — for example
`vsock://10:9734`. The wizard detects the `vsock://` prefix and prompts for
the token.

Or configure `.mcp.json` manually:

```json
{
  "mcpServers": {
    "sysknife": {
      "command": "/path/to/sysknife",
      "args": ["mcp-server"],
      "env": {
        "SYSKNIFE_SOCKET": "vsock://10:9734",
        "SYSKNIFE_TOKEN": "<your-hex-token>",
        "SYSKNIFE_LLM_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "<your-api-key>"
      }
    }
  }
}
```

### Test the vsock connection

```sh
sysknife --dry-run "check disk usage"
```

---

## 3. Reload the MCP client

In Claude Code, run `/reload-plugins` to pick up the new `.mcp.json`. The
`sysknife_plan` and `sysknife_execute` tools should appear in the tool list.

---

## Troubleshooting

### "connection refused" or "no such file or directory"

- **SSH tunnel:** confirm the tunnel is running: `ls -la /tmp/sysknife-vm.sock`
- **vsock:** confirm `vhost_vsock` is loaded (`lsmod | grep vhost_vsock`) and
  the CID is correct (`cat /sys/class/vsock/local_cid` inside the guest)
- Confirm the daemon is running: `systemctl status sysknife-daemon` inside the
  guest

### "SYSKNIFE_TOKEN is not set; vsock connections require a pre-shared token"

Set `SYSKNIFE_TOKEN` in the `env` block of `.mcp.json` (see above).

### "authentication failed" on vsock

The token on the host (`SYSKNIFE_TOKEN` in `.mcp.json`) does not match any
entry in `/etc/sysknife/token` on the guest. Verify both match exactly.

### SSH tunnel drops when the terminal closes

Use `ssh -fN` (forks, no command) or run it via a systemd user unit or
`tmux`/`screen` session. Alternatively switch to vsock which does not depend
on SSH.

### vsock not available in the guest

Check: `ls /dev/vsock` inside the guest. If absent, the VM was started without
a vsock device — add the `<vsock>` element to the libvirt XML (see above) and
restart the VM.

---

## Security notes

- **SSH tunnel:** the tunnel is authenticated by your SSH keypair. No extra
  secrets are needed.
- **vsock:** the pre-shared token (`SYSKNIFE_TOKEN`) prevents other host
  processes from connecting. Keep it out of version control — add `.mcp.json`
  to `.gitignore`.
- **Socket file permissions:** the daemon socket at `/run/sysknife/daemon.sock`
  is owned by `root:sysknife` with mode `0660` — only members of the
  `sysknife` group can connect locally. The SSH tunnel and vsock bypass this
  by terminating at the daemon's authenticated IPC layer.
