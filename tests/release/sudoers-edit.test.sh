#!/usr/bin/env bash
# Guards sysknife-sudoers-edit against writing a grant that is `ALL` under
# another name, and guards its screen against drifting from the daemon's.
#
# `packaging/sysknife-sudoers` opens by stating that no shell or general runuser
# grant is permitted. Both this helper and executor.rs enforced that against the
# literal string "ALL", and the command validator accepts any absolute path with
# a safe charset, which /bin/bash satisfies. `visudo -cf` accepts
# `u ALL=(root) NOPASSWD: /bin/bash`, so nothing below the two screens would
# have caught it.
#
# The helper is reachable directly through its wildcard NOPASSWD grant, which
# skips the preview, the receipt and the signed chain, so it has to hold the line
# itself. Its list is compared against the daemon's by parsing the daemon's
# source, because a copy here would drift the way the grub helper's copy drifted
# (GHSA-f8vp-j3jh-7wjx).
#
# Pure-function test: no root, no visudo, no writes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/packaging/sysknife-sudoers-edit"

[ -f "$SCRIPT" ] || { echo "FAIL: $SCRIPT not found"; exit 1; }

python3 - "$SCRIPT" <<'PY'
import importlib.util
import os
import re
import sys
from importlib.machinery import SourceFileLoader

script_path = sys.argv[1]
loader = SourceFileLoader("sudoers_edit", script_path)
spec = importlib.util.spec_from_loader("sudoers_edit", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

failures = []

build_rule = getattr(mod, "build_rule", None)
if build_rule is None:
    print("FAIL: build_rule() missing from sysknife-sudoers-edit")
    sys.exit(1)


def refused(commands, nopasswd=True):
    """True when build_rule dies on this command list."""
    try:
        build_rule("deploy", "root", nopasswd, commands)
    except SystemExit as exc:
        return exc.code != 0
    return False


# 1. A passwordless shell-equivalent grant must be refused, in every spelling
#    that reaches the same end state.
for commands in [
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/bash",
    "/usr/local/bin/bash",
    "/BIN/BASH",
    "/bin/busybox",
    "/usr/bin/su",
    "/usr/bin/runuser",
    "/usr/bin/python3",
    "/usr/bin/perl",
    "/usr/bin/awk",
    "/usr/bin/vim",
    "/usr/bin/less",
    "/usr/bin/env",
    "/usr/bin/find",
    "/usr/bin/tar",
    "/usr/bin/git",
    "/usr/bin/systemctl",
    "/usr/bin/docker",
    # A list is as wide as its widest member.
    "/usr/sbin/nginx,/bin/bash",
    # The original case, which must keep being refused.
    "ALL",
]:
    if not refused(commands):
        failures.append(
            f"--commands {commands!r} --nopasswd was accepted; that rule is a standing "
            "passwordless root shell")

# 2. Narrow grants must survive, or the screen has eaten the feature.
for commands in ["/usr/sbin/nginx", "/usr/bin/uptime", "/usr/bin/df",
                 "/usr/sbin/logrotate", "/usr/sbin/nginx,/usr/bin/df"]:
    if refused(commands):
        failures.append(
            f"--commands {commands!r} --nopasswd was refused, but it is a narrow grant")

# 3. With the password prompt kept, a broad grant is permitted. That is the line
#    this repository draws, and "ALL" has always been permitted that way, so
#    refusing one spelling of it here would be a stricter policy applied unevenly.
for commands in ["/bin/bash", "ALL"]:
    if refused(commands, nopasswd=False):
        failures.append(
            f"--commands {commands!r} without --nopasswd was refused; the password prompt "
            "is the concession this policy asks for")

# 4. PARITY with the daemon's own list, derived rather than restated.
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(script_path)))
validate_rs = os.path.join(repo_root, "crates/sysknife-daemon/src/actions/validate.rs")
try:
    rust_src = open(validate_rs, encoding="utf-8").read()
except OSError as exc:
    failures.append(f"cannot read {validate_rs}: {exc}; the parity check inspected nothing")
    rust_src = ""
decl = re.search(r"SHELL_EQUIVALENT_COMMANDS:\s*&\[&str\]\s*=\s*&\[(.*?)\];", rust_src, re.S)
if decl is None:
    failures.append(
        "SHELL_EQUIVALENT_COMMANDS not found in validate.rs; this check would pass over "
        "an empty set, so it fails instead")
else:
    daemon_cmds = set(re.findall(r'"([^"]+)"', decl.group(1)))
    if not daemon_cmds:
        failures.append(
            "SHELL_EQUIVALENT_COMMANDS parsed as empty; refusing to compare against nothing")
    helper_cmds = set(getattr(mod, "SHELL_EQUIVALENT_COMMANDS", ()))
    if not helper_cmds:
        failures.append("the helper has no SHELL_EQUIVALENT_COMMANDS; it screens nothing")
    missing = sorted(daemon_cmds - helper_cmds)
    if missing:
        failures.append(
            f"the helper's list is missing {missing}, which the daemon refuses; a direct "
            "sudo call to this helper bypasses the daemon entirely")
    extra = sorted(helper_cmds - daemon_cmds)
    if extra:
        failures.append(
            f"the helper refuses {extra}, which the daemon accepts; a grant that works "
            "through the daemon and fails through the helper is a bug report nobody can "
            "reproduce")
    # And prove it behaviourally, so the lists agreeing is not the only evidence.
    for cmd in sorted(daemon_cmds):
        if not refused(f"/usr/bin/{cmd}"):
            failures.append(
                f"--commands /usr/bin/{cmd} --nopasswd was accepted; the daemon refuses it")

# 5. WIRING: op_grant must go through build_rule. Drive it and assert it exits
#    non-zero before touching /etc/sudoers.d.
class Args:
    name = "deploy-helper"
    user = "deploy"
    runas = "root"
    commands = "/bin/bash"
    nopasswd = True

op_grant = getattr(mod, "op_grant", None)
if op_grant is None:
    failures.append("op_grant() missing; the wiring check inspected nothing")
else:
    opened = {"path": None}
    real_open = open

    def tracking_open(path, *a, **kw):
        opened["path"] = str(path)
        return real_open(path, *a, **kw)

    mod.open = tracking_open
    try:
        op_grant(Args())
    except SystemExit as exc:
        if exc.code == 0:
            failures.append("op_grant exited 0 for a NOPASSWD /bin/bash grant")
    except Exception as exc:  # noqa: BLE001
        failures.append(f"op_grant raised {exc!r} instead of refusing cleanly")
    else:
        failures.append("op_grant returned without refusing a NOPASSWD /bin/bash grant")
    finally:
        del mod.open
    if opened["path"] and "sudoers" in opened["path"]:
        failures.append(
            f"op_grant opened {opened['path']!r} before refusing; the screen must run first")

if failures:
    for f in failures:
        print(f"FAIL: {f}")
    sys.exit(1)

print("ok: sysknife-sudoers-edit refuses ALL-equivalent grants and matches the daemon's list")
PY
