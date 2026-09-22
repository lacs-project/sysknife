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

class Args:
    def __init__(self, mountpoint, device="//host/share", fstype="cifs", options=None):
        self.mountpoint = mountpoint
        self.device = device
        self.fstype = fstype
        self.options = options


def op_refuses_before_mount(op, mp):
    """Run op_mount/op_unmount with a bad mountpoint and assert it dies BEFORE any
    mount(8)/umount(8) is invoked. Patches subprocess.run so no real (u)mount and
    no fstab write can happen even if the guard were removed — that is the point:
    a removed guard makes the fake fire, failing this test instead of mounting."""
    called = {"ran": False}

    class FakeCompleted:
        returncode = 1
        stderr = b"blocked by test double"

    def fake_run(cmd, **kw):
        called["ran"] = True
        return FakeCompleted()

    real_run = mod.subprocess.run
    mod.subprocess.run = fake_run
    try:
        op(Args(mp))
        died = False
    except SystemExit as exc:
        died = exc.code != 0
    finally:
        mod.subprocess.run = real_run
    return died and not called["ran"]


def op_refuses_before_mount_with_options(options):
    """Drive op_mount with a clean mountpoint and the given options, asserting
    it dies before invoking mount(8). The mountpoint is valid, so only the
    option screen can refuse."""
    called = {"ran": False}

    class FakeCompleted:
        returncode = 1
        stderr = b"blocked by test double"

    def fake_run(cmd, **kw):
        called["ran"] = True
        return FakeCompleted()

    real_run = mod.subprocess.run
    mod.subprocess.run = fake_run
    try:
        with tempfile.TemporaryDirectory() as d:
            mp = os.path.join(d, "mnt")
            os.makedirs(mp)
            mod.op_mount(Args(mp, options=options))
        died = False
    except SystemExit as exc:
        died = exc.code != 0
    finally:
        mod.subprocess.run = real_run
    return died and not called["ran"]


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

    # 3b. Pre-existing ordinary directory -> accepted (over-blocking regression guard).
    existing = os.path.join(d, "existing")
    os.mkdir(existing)
    if not accepts(existing):
        failures.append(f"pre-existing ordinary mountpoint {existing} was wrongly refused")

    # 3c. Dangling symlink as the mountpoint -> refused (islink is lstat-based).
    dangling = os.path.join(d, "dangling")
    os.symlink(os.path.join(d, "nonexistent"), dangling)
    if not rejects(dangling):
        failures.append(f"dangling symlink mountpoint {dangling} was NOT refused")

# 4./5. Trailing-slash and double-slash forms resolving to a critical path -> refused.
if not rejects("/etc/"):
    failures.append("trailing-slash '/etc/' bypassed the critical-mountpoint denylist")
if not rejects("//etc"):
    failures.append("'//etc' bypassed the critical-mountpoint denylist")

# 6. Other critical targets, not just /etc, are refused when reached via symlink.
with tempfile.TemporaryDirectory() as d2:
    for crit in ("/proc", "/sys", "/boot"):
        s = os.path.join(d2, "to" + crit.replace("/", "_"))
        os.symlink(crit, s)
        if not rejects(s):
            failures.append(f"symlink to critical {crit} ({s}) was NOT refused")

# 7. WIRING: op_mount must invoke the guard BEFORE any mount. A direct critical
#    target needs the static guard (O_NOFOLLOW alone would open the real /etc dir
#    and mount over it), so this fails if the guard call is removed or reordered.
if not op_refuses_before_mount(mod.op_mount, "/etc/"):
    failures.append("op_mount did NOT refuse '/etc/' before invoking mount(8)")

with tempfile.TemporaryDirectory() as d3:
    smp = os.path.join(d3, "sneaky")
    os.symlink("/etc", smp)
    if not op_refuses_before_mount(mod.op_mount, smp):
        failures.append("op_mount did NOT refuse a symlinked mountpoint before mount(8)")

# 8. WIRING: op_unmount must refuse a symlinked mountpoint before umount(8).
with tempfile.TemporaryDirectory() as d4:
    ump = os.path.join(d4, "umlink")
    os.symlink("/home", ump)
    if not op_refuses_before_mount(mod.op_unmount, ump):
        failures.append("op_unmount did NOT refuse a symlinked mountpoint before umount(8)")

# 9. The swap operations resolve ANCESTORS, not just the final component.
#    O_EXCL|O_NOFOLLOW on the leaf says nothing about the directories above it.
#    A local user who owns any directory entry can have AddSwap create
#    <dir>/swapfile once, replace <dir> with a symlink to a directory they do
#    not own, and call AddSwap again: root then creates a file of up to 1 TiB
#    inside the symlink target, and RemoveSwap unlinks inside it. No race is
#    needed, because the attacker owns the entry outright.
#
#    op_mount has resolved the whole path with realpath since #155. The swap
#    operations were never given the same treatment.
swap_guard = getattr(mod, "assert_swap_path_safe", None)
if swap_guard is None:
    failures.append("assert_swap_path_safe() missing from sysknife-mount-edit")
else:
    def swap_rejects(path):
        try:
            swap_guard(path)
        except SystemExit as exc:
            return exc.code != 0
        return False

    with tempfile.TemporaryDirectory() as d5:
        real = os.path.join(d5, "real")
        victim = os.path.join(d5, "victim")
        os.makedirs(real)
        os.makedirs(victim)
        # An ancestor the attacker controls, pointed somewhere they do not own.
        hop = os.path.join(d5, "hop")
        os.symlink(victim, hop)
        if not swap_rejects(os.path.join(hop, "swapfile")):
            failures.append("a swap path reached through a symlinked ANCESTOR was NOT refused")
        # The leaf case, which O_EXCL|O_NOFOLLOW already covers at create time;
        # the guard must refuse it too so rmswap gets the same answer as addswap.
        leaf = os.path.join(real, "leaf")
        os.symlink(os.path.join(victim, "target"), leaf)
        if not swap_rejects(leaf):
            failures.append("a swap path whose final component is a symlink was NOT refused")
        # A path with no symlink anywhere must still be allowed, or the guard
        # is just an outage.
        try:
            swap_guard(os.path.join(real, "swapfile"))
        except SystemExit:
            failures.append("a swap path with no symlink in it was refused; the guard is too wide")

# 10. WIRING: both swap ops must reach that guard BEFORE they execute anything
#     as root. subprocess.run is faked, so a missing guard fires the fake rather
#     than running dd/mkswap/swapon or swapoff.
def swap_op_refuses_before_exec(op, path, size_mb=1):
    called = {"ran": False}

    class FakeCompleted:
        returncode = 1
        stderr = b"blocked by test double"

    def fake_run(cmd, **kw):
        called["ran"] = True
        return FakeCompleted()

    class SwapArgs:
        def __init__(self, file, size_mb):
            self.file = file
            self.size_mb = size_mb

    real_run = mod.subprocess.run
    mod.subprocess.run = fake_run
    try:
        op(SwapArgs(path, size_mb))
        died = False
    except SystemExit as exc:
        died = exc.code != 0
    finally:
        mod.subprocess.run = real_run
    return died and not called["ran"]


with tempfile.TemporaryDirectory() as d6:
    victim6 = os.path.join(d6, "victim")
    os.makedirs(victim6)
    hop6 = os.path.join(d6, "hop")
    os.symlink(victim6, hop6)
    target6 = os.path.join(hop6, "swapfile")

    if not swap_op_refuses_before_exec(mod.op_addswap, target6):
        failures.append("op_addswap did NOT refuse a symlinked ancestor before executing anything")

    # The GRANDPARENT case, which is the one only the realpath guard can catch.
    # O_DIRECTORY|O_NOFOLLOW on the parent rejects a parent that is itself a
    # link, so the one-level case above passes even with the guard deleted.
    # Here the parent ("sub") is a real directory reached THROUGH the link, so
    # opening it succeeds and the create lands in the victim directory. A
    # mutation that removes assert_swap_path_safe must fail here.
    os.makedirs(os.path.join(victim6, "sub"))
    deep6 = os.path.join(hop6, "sub", "swapfile")
    if not swap_op_refuses_before_exec(mod.op_addswap, deep6):
        failures.append("op_addswap did NOT refuse a symlinked GRANDPARENT before executing anything")
    if os.listdir(os.path.join(victim6, "sub")):
        failures.append(
            f"op_addswap created {os.listdir(os.path.join(victim6, 'sub'))} through a symlinked grandparent")
    # Nothing may have been created through the link, whatever the exit code was.
    if "swapfile" in os.listdir(victim6):
        failures.append("op_addswap created a swapfile inside the symlink target")

    # rmswap consults known_swap_files() first, so declare the path in a staged
    # fstab. Without this the test would pass for the wrong reason.
    staged = os.path.join(d6, "fstab")
    with open(staged, "w") as fh:
        fh.write(f"{target6}\tnone\tswap\tsw,nofail\t0\t0\n")
    real_fstab, real_swaps = mod.FSTAB, mod.PROC_SWAPS
    mod.FSTAB, mod.PROC_SWAPS = staged, os.path.join(d6, "no-such-swaps")
    try:
        if target6 not in mod.known_swap_files():
            failures.append("the staged fstab did not register the path, so the rmswap case is vacuous")
        elif not swap_op_refuses_before_exec(mod.op_rmswap, target6):
            failures.append("op_rmswap did NOT refuse a symlinked ancestor before executing anything")
    finally:
        mod.FSTAB, mod.PROC_SWAPS = real_fstab, real_swaps

# 11. PARITY with the daemon's mount-option denylist, derived rather than
#     restated. The helper is directly sudo-invocable through its wildcard
#     grant, so the daemon refusing `suid` and `dev` does not bind it. Reading
#     the Rust list here is the point: a copy would drift the way
#     grub-kargs-edit's DENY_UNIT_TARGETS drifted.
import re as _re

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(script_path)))
validate_rs = os.path.join(repo_root, "crates/sysknife-daemon/src/actions/validate.rs")
try:
    rust_src = open(validate_rs, encoding="utf-8").read()
except OSError as exc:
    failures.append(f"cannot read {validate_rs}: {exc}; the parity check inspected nothing")
    rust_src = ""
decl = _re.search(r"MOUNT_OPTIONS_DENY:\s*&\[&str\]\s*=\s*&\[(.*?)\];", rust_src, _re.S)
if decl is None:
    failures.append(
        "MOUNT_OPTIONS_DENY not found in validate.rs; this check would pass over an "
        "empty set, so it fails instead")
else:
    daemon_deny = set(_re.findall(r'"([^"]+)"', decl.group(1)))
    if not daemon_deny:
        failures.append("MOUNT_OPTIONS_DENY parsed as empty; refusing to compare against nothing")
    helper_deny = {o.lower() for o in getattr(mod, "DENY_MOUNT_OPTIONS", ())}
    missing = sorted(daemon_deny - helper_deny)
    if missing:
        failures.append(
            f"DENY_MOUNT_OPTIONS is missing {missing}, which the daemon refuses; a direct "
            "sudo call to this helper mounts with them")
    # And behaviourally, through the helper's own screen.
    for opt in sorted(daemon_deny):
        for spelling in (opt, opt.upper(), f"ro,{opt}"):
            if not op_refuses_before_mount_with_options(spelling):
                failures.append(f"--options {spelling!r} was accepted; it grants privilege")
    # The hardening must be added, not only demanded.
    hardened = mod.ensure_hardened("defaults")
    if "nosuid" not in hardened or "nodev" not in hardened:
        failures.append(f"ensure_hardened('defaults') returned {hardened!r}, which still permits suid/dev")
    if mod.ensure_hardened("nosuid,nodev,ro") != "nosuid,nodev,ro":
        failures.append("ensure_hardened repeats options that are already present")
    # WIRING. Testing ensure_hardened alone passes with the call to it deleted
    # from op_mount, which is the defect this repository catches most. Capture
    # the argv mount(8) would actually receive.
    captured = {"argv": None}

    def capture_run(cmd, **kw):
        if captured["argv"] is None and any("mount" in str(c) for c in cmd[:1]):
            captured["argv"] = list(cmd)

        class R:
            returncode = 1
            stderr = b"blocked by test double"
        return R()

    real_run = mod.subprocess.run
    mod.subprocess.run = capture_run
    try:
        with tempfile.TemporaryDirectory() as d7:
            mp7 = os.path.join(d7, "mnt")
            os.makedirs(mp7)
            try:
                mod.op_mount(Args(mp7, options="ro"))
            except SystemExit:
                pass
    finally:
        mod.subprocess.run = real_run
    if captured["argv"] is None:
        failures.append("op_mount never invoked mount(8), so the option wiring was not observed")
    else:
        argv = captured["argv"]
        opts = argv[argv.index("-o") + 1] if "-o" in argv else ""
        if "nosuid" not in opts or "nodev" not in opts:
            failures.append(
                f"op_mount passed -o {opts!r} to mount(8); the hardening is computed and not used")

if failures:
    for f in failures:
        print("FAIL:", f)
    sys.exit(1)
print("ok: sysknife-mount-edit refuses symlinked and critical-resolving mountpoints")
print("ok: op_mount and op_unmount invoke the guard before any (u)mount")
print("ok: the swap operations refuse a symlinked ancestor before running anything")
print("ok: the helper refuses every mount option the daemon denies, and hardens the rest")
PY