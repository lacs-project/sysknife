#!/usr/bin/env bash
# Guards sysknife-mount-edit's rmswap against the arbitrary-root-unlink class.
#
# op_rmswap charset-validated its --file and then os.unlink()d it as root. Every
# step before the unlink tolerates a non-swap path: swapoff runs with check=False
# so it fails silently, and the fstab rewrite is a no-op when no entry matches.
# `--file /etc/shadow` therefore reached the unlink and deleted the shadow file.
# The helper must only remove a path the host actually knows as a swap file.
# Pure-function test: no root, no real swapoff, no writes outside a tempdir.
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
loader = SourceFileLoader("mount_edit", script_path)
spec = importlib.util.spec_from_loader("mount_edit", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

failures = []

if getattr(mod, "known_swap_files", None) is None:
    print("FAIL: known_swap_files() missing from sysknife-mount-edit")
    sys.exit(1)
if getattr(mod, "PROC_SWAPS", None) is None:
    print("FAIL: PROC_SWAPS missing from sysknife-mount-edit")
    sys.exit(1)


class Args:
    def __init__(self, file):
        self.file = file


class FakeCompleted:
    returncode = 0
    stderr = b""


def run_rmswap(path):
    """Run op_rmswap with swapoff stubbed out. Returns the SystemExit code, or
    None if it ran to completion."""
    real_run = mod.subprocess.run
    mod.subprocess.run = lambda *a, **k: FakeCompleted()
    try:
        mod.op_rmswap(Args(path))
        return None
    except SystemExit as exc:
        return exc.code
    finally:
        mod.subprocess.run = real_run


with tempfile.TemporaryDirectory() as d:
    fstab = os.path.join(d, "fstab")
    swaps = os.path.join(d, "swaps")
    victim = os.path.join(d, "shadow")
    declared = os.path.join(d, "declared-swap")
    active = os.path.join(d, "active-swap")

    with open(victim, "w") as fh:
        fh.write("root:!:19000:0:99999:7:::\n")
    for p in (declared, active):
        with open(p, "w") as fh:
            fh.write("swapdata")

    with open(fstab, "w") as fh:
        fh.write("UUID=1234\t/\text4\tdefaults\t0\t1\n")
        fh.write(f"{declared}\tnone\tswap\tsw,nofail\t0\t0\n")
        # A commented-out entry must not make a path "known".
        fh.write(f"#{victim}\tnone\tswap\tsw,nofail\t0\t0\n")
    with open(swaps, "w") as fh:
        fh.write("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n")
        fh.write(f"{active}\t\t\t\tfile\t\t2097148\t\t0\t\t-2\n")
        fh.write("/dev/sda2\t\t\t\tpartition\t2097148\t\t0\t\t-3\n")

    mod.FSTAB = fstab
    mod.PROC_SWAPS = swaps

    # 1. known_swap_files sees the fstab declaration and the active file, and
    #    neither the commented-out line nor the swap *partition*.
    known = mod.known_swap_files()
    if declared not in known:
        failures.append("known_swap_files missed the fstab-declared swap file")
    if active not in known:
        failures.append("known_swap_files missed the active /proc/swaps file")
    if victim in known:
        failures.append("known_swap_files treated a commented-out fstab line as a swap file")
    if "/dev/sda2" in known:
        failures.append("known_swap_files treated a swap partition as a removable swap file")

    # 2. THE BUG: an unrelated root-owned file must not be deleted.
    code = run_rmswap(victim)
    if code in (None, 0):
        failures.append(f"op_rmswap did NOT refuse an unknown path (exit {code!r})")
    if not os.path.exists(victim):
        failures.append("op_rmswap DELETED a file that is not a swap file")

    # 3. A symlink that happens to be declared as swap is still not ours to
    #    follow — unlink removes the link, but accepting it means fstab content
    #    decides what root deletes.
    link = os.path.join(d, "link-swap")
    os.symlink(victim, link)
    with open(fstab, "a") as fh:
        fh.write(f"{link}\tnone\tswap\tsw,nofail\t0\t0\n")
    code = run_rmswap(link)
    if code in (None, 0):
        failures.append(f"op_rmswap did NOT refuse a symlinked swap path (exit {code!r})")

    # 4. The action must still work: a genuine, declared swap file is removed.
    code = run_rmswap(declared)
    if code not in (None, 0):
        failures.append(f"op_rmswap refused a legitimate declared swap file (exit {code!r})")
    if os.path.exists(declared):
        failures.append("op_rmswap did not remove a legitimate declared swap file")

    # 5. ...and so is one that is only known because it is currently active.
    code = run_rmswap(active)
    if code not in (None, 0):
        failures.append(f"op_rmswap refused a legitimate active swap file (exit {code!r})")
    if os.path.exists(active):
        failures.append("op_rmswap did not remove a legitimate active swap file")

if failures:
    for f in failures:
        print("FAIL:", f)
    sys.exit(1)
print("ok: sysknife-mount-edit only removes paths the host knows as swap files")
print("ok: rmswap still removes genuine declared and active swap files")
PY
