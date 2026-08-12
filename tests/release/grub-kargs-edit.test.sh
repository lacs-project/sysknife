#!/usr/bin/env bash
# Guards sysknife-grub-kargs-edit against boot-security downgrades, in both
# directions, and guards the two directions against drifting apart.
#
# The helper screened --append only, on the stated premise that "removing an arg
# is always safe". The premise inverts the risk: the dangerous move is removing a
# PROTECTIVE arg. Deleting `module.sig_enforce=1` or `lockdown=confidentiality`
# reaches the same next-boot state as appending its weakening counterpart, which
# the append screen already refuses. The helper is reachable directly through the
# sudoers grant, so it must enforce this itself and not lean on the daemon.
# Pure-function test: no root, no GRUB, no writes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/packaging/sysknife-grub-kargs-edit"

[ -f "$SCRIPT" ] || { echo "FAIL: $SCRIPT not found"; exit 1; }

python3 - "$SCRIPT" <<'PY'
import importlib.util
import sys
from importlib.machinery import SourceFileLoader

script_path = sys.argv[1]
loader = SourceFileLoader("grub_kargs_edit", script_path)
spec = importlib.util.spec_from_loader("grub_kargs_edit", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

failures = []

guard = getattr(mod, "reject_dangerous_delete", None)
if guard is None:
    print("FAIL: reject_dangerous_delete() missing from sysknife-grub-kargs-edit")
    sys.exit(1)


def refused(tok):
    try:
        guard([tok])
    except SystemExit as exc:
        return exc.code != 0
    return False


# 1. Removing a protective arg is a downgrade and must be refused. These mirror
#    validated_safe_kernel_arg_removal in crates/sysknife-daemon/src/executor.rs.
PROTECTIVE = [
    "lockdown=confidentiality",
    "module.sig_enforce=1",
    "selinux=1",
    "enforcing=1",
    "apparmor=1",
    "security=selinux",
    "pti=on",
    "mitigations=auto,nosmt",
    "init_on_alloc=1",
    "init_on_free=1",
    "slab_nomerge",
    "page_alloc.shuffle=1",
    "randomize_kstack_offset=on",
    "slub_debug=FZP",
    "vsyscall=none",
    "debugfs=off",
    "iommu=force",
    "intel_iommu=on",
    "amd_iommu=force_isolation",
    "nosmt",
    "kaslr",
    # Case must not launder it.
    "LOCKDOWN=integrity",
    "Module.Sig_Enforce=1",
]
for tok in PROTECTIVE:
    if not refused(tok):
        failures.append(f"--delete {tok!r} was accepted; removing it weakens the next boot")

# 2. An arg that is itself a weakening stays removable, or SysKnife could never
#    harden a host that already boots with one.
WEAKENING = [
    "mitigations=off",
    "selinux=0",
    "enforcing=0",
    "apparmor=0",
    "pti=off",
    "lockdown=none",
    "debugfs=on",
    "module.sig_enforce=0",
    "init_on_alloc=0",
    "init=/bin/sh",
    "single",
    "nokaslr",
]
for tok in WEAKENING:
    if refused(tok):
        failures.append(f"--delete {tok!r} was refused, but removing it hardens the host")

# 3. Ordinary args stay removable — the screen must not become "no deletions".
ORDINARY = ["quiet", "splash", "nomodeset", "console=ttyS0", "rd.driver.blacklist=nouveau"]
for tok in ORDINARY:
    if refused(tok):
        failures.append(f"--delete {tok!r} was refused, but it carries no security meaning")

# 3b. DRIFT GUARD between the two screens. The --delete screen lets WEAKENING
#     through on the stated grounds that each one IS the downgrade, so removing
#     it hardens the host. That reasoning binds the other direction: if removing
#     X hardens, then adding X weakens, and --append must refuse every one of
#     them. The two lists were written separately and drifted -- --delete knew
#     about apparmor=, mitigations= and module.sig_enforce=, --append did not --
#     so `--append apparmor=0` disabled Ubuntu's MAC on the next boot while
#     `--delete apparmor=1` was correctly refused. Deriving this list from
#     WEAKENING rather than retyping it is the point: a token added to one
#     screen cannot be forgotten in the other.
append_guard = getattr(mod, "reject_dangerous_append", None)
if append_guard is None:
    print("FAIL: reject_dangerous_append() missing from sysknife-grub-kargs-edit")
    sys.exit(1)


def refused_append(tok):
    try:
        append_guard([tok])
    except SystemExit as exc:
        return exc.code != 0
    return False


for tok in WEAKENING:
    if not refused_append(tok):
        failures.append(
            f"--append {tok!r} was accepted, but --delete treats it as a weakening; "
            "the two screens have drifted"
        )

# 3c. The debug shell, by its own name rather than through systemd.unit=.
#     `systemd.unit=debug-shell.service` is refused via DENY_UNIT_TARGETS, but
#     systemd-debug-generator also honours systemd.debug_shell, which reaches
#     the identical end state: debug-shell.service pulled into the boot
#     transaction, root shell on tty9, no login. Underscore is the real spelling
#     (verified against systemd-debug-generator(8) on Ubuntu 24.04); the hyphen
#     forms are screened too so a near-miss cannot creep back.
DEBUG_SHELL = [
    "systemd.debug_shell=1",
    "systemd.debug_shell",
    "rd.systemd.debug_shell=1",
    "systemd.debug-shell=1",
    "SYSTEMD.DEBUG_SHELL=1",
]
for tok in DEBUG_SHELL:
    if not refused_append(tok):
        failures.append(f"--append {tok!r} was accepted; it boots into a root shell on tty9")

# 3d. Ordinary appends must survive, or the screen has eaten the feature.
for tok in ["quiet", "splash", "nomodeset", "console=ttyS0", "transparent_hugepage=madvise"]:
    if refused_append(tok):
        failures.append(f"--append {tok!r} was refused, but it carries no security meaning")

# 4. WIRING: main() must call the screen. Drive it end to end with a protective
#    --delete and assert it exits non-zero before reading /etc/default/grub.
argv = sys.argv[:]
sys.argv = ["sysknife-grub-kargs-edit", "--delete", "module.sig_enforce=1"]
opened = {"path": None}
real_open = mod.open if hasattr(mod, "open") else None
import builtins
real_builtin_open = builtins.open


def tracking_open(path, *a, **k):
    opened["path"] = path
    return real_builtin_open(path, *a, **k)


builtins.open = tracking_open
try:
    mod.main()
    failures.append("main() did NOT refuse a protective --delete")
except SystemExit as exc:
    if exc.code in (None, 0):
        failures.append(f"main() exited {exc.code!r} on a protective --delete")
finally:
    builtins.open = real_builtin_open
    sys.argv = argv

if opened["path"] is not None:
    failures.append(f"main() opened {opened['path']!r} before refusing the delete")

if failures:
    for f in failures:
        print("FAIL:", f)
    sys.exit(1)
print("ok: sysknife-grub-kargs-edit refuses to delete protective kernel arguments")
print("ok: weakening and ordinary arguments stay deletable")
print("ok: every arg the delete screen calls a weakening is refused on --append")
print("ok: --append refuses systemd.debug_shell in all its spellings")
print("ok: ordinary arguments stay appendable")
print("ok: main() screens --delete before touching /etc/default/grub")
PY
