#!/usr/bin/env bash
# Guards sysknife-mount-edit against the symlinked-mountpoint class (#155, #148).
# os.makedirs(exist_ok=True) and mount(8) both follow symlinks, so a mountpoint
# like /tmp/x -> /etc would otherwise mount an attacker share over /etc. The
# script must resolve the mountpoint and refuse a symlink or a critical target
# BEFORE it touches the filesystem. Pure-function test: no root, no real mount.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/packaging/sysknife-mount-edit"

[ -f "$SCRIPT" ] || { echo "FAIL: $SCRIPT not found"; exit 1; }

python3 - "$SCRIPT" <<'PY'
import importlib.util
import os
import sys
import tempfile
from importlib.machinery import SourceFileLoader

script_path = sys.argv[1]
# The script has no .py suffix, so name a SourceFileLoader explicitly.
loader = SourceFileLoader("mount_edit", script_path)
spec = importlib.util.spec_from_loader("mount_edit", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

guard = getattr(mod, "assert_mountpoint_safe", None)
assert guard is not None, "assert_mountpoint_safe() missing from sysknife-mount-edit"

def rejects(mp):
    try:
        guard(mp)
    except SystemExit as exc:
        return exc.code != 0
    return False

def accepts(mp):
    try:
        guard(mp)
        return True
    except SystemExit:
        return False

failures = []

with tempfile.TemporaryDirectory() as d:
    # 1. Final component is a symlink to /etc -> must be refused.
    link = os.path.join(d, "evil")
    os.symlink("/etc", link)
    if not rejects(link):
        failures.append(f"symlink-to-/etc mountpoint {link} was NOT refused")

    # 2. Parent component is a symlink -> resolved path escapes -> refused.
    if not rejects(os.path.join(link, "sub")):
        failures.append("mountpoint reached through a parent symlink was NOT refused")

    # 3. Ordinary, not-yet-existing mountpoint under a real dir -> accepted.
    real_target = os.path.join(d, "data")
    if not accepts(real_target):
        failures.append(f"ordinary mountpoint {real_target} was wrongly refused")

# 4. Trailing-slash bypass of the critical-path denylist -> refused.
if not rejects("/etc/"):
    failures.append("trailing-slash '/etc/' bypassed the critical-mountpoint denylist")

# 5. Double-slash form resolving to a critical path -> refused.
if not rejects("//etc"):
    failures.append("'//etc' bypassed the critical-mountpoint denylist")

if failures:
    for f in failures:
        print("FAIL:", f)
    sys.exit(1)
print("ok: sysknife-mount-edit refuses symlinked and critical-resolving mountpoints")
PY