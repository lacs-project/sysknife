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
import os
import re
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
#     `systemd.unit=debug-shell.service` is refused like any unlisted key, but
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

# 3c'. lockdown= takes only its two hardening values. The denylist refused every
#     lockdown= value; the allowlist accepts `integrity` and `confidentiality`,
#     which raise the lockdown level, and nothing else.
for tok in ["lockdown=none", "lockdown=", "LOCKDOWN=none", "lockdown=integrityx", "lockdown"]:
    if not refused_append(tok):
        failures.append(f"--append {tok!r} was accepted; only lockdown=integrity and =confidentiality are")

# 3c''. Boot-mode and run tokens systemd(1) and kernel-command-line(7) honour.
#     `emergency`, `rescue`, `-b` and runlevels 2-5 pick the boot target the way
#     `single` and `1` already did; `systemd.run=` runs a command as a root
#     service after boot; `rdinit=` and `rd.systemd.unit=` are the initramfs
#     twins of `init=` and `systemd.unit=`; `rd.break` and `break` stop in an
#     initramfs root shell. Both copies accepted every one.
BOOT_MODE = [
    "emergency", "rescue", "-b", "rd.emergency", "rd.rescue", "2", "3", "4", "5",
    "systemd.run=/tmp/x", "systemd.run_success_action=reboot",
    "systemd.run_failure_action=none", "rdinit=/bin/sh", "rd.break", "rd.break=pre-mount",
    "break", "break=premount", "rd.systemd.unit=emergency.target",
    "rd.systemd.unit=rescue.target", "rd.systemd.unit=debug-shell.service",
    "EMERGENCY", "Systemd.Run=/tmp/x",
]
for tok in BOOT_MODE:
    if not refused_append(tok):
        failures.append(f"--append {tok!r} was accepted; it boots into a root shell or command")

# 3c'''. The denylists these screens used before the allowlist, kept as refuse
#     cases: every token they named, and each prefix with a value after it, must
#     still be refused on --append.
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(script_path)))
exec_rs = os.path.join(repo_root, "crates/sysknife-daemon/src/executor.rs")
try:
    exec_src = open(exec_rs, encoding="utf-8").read()
except OSError as exc:
    failures.append(f"cannot read {exec_rs}: {exc}; the parity check inspected nothing")
    exec_src = ""
FORMER_PREFIXES = [
    "init=", "selinux=0", "enforcing=0", "security=", "module_blacklist=", "apparmor=0",
    "mitigations=off", "lockdown=", "pti=off", "systemd.debug_shell", "systemd.debug-shell",
    "rd.systemd.debug_shell", "rd.systemd.debug-shell", "systemd.run", "rdinit=", "rd.break",
    "break", "lsm=", "modprobe.blacklist=", "rd.shell", "systemd.mask=", "rd.systemd.mask=",
    "audit=0", "spectre_v2=off", "spec_store_bypass_disable=off",
]
FORMER_EXACT = [
    "single", "s", "1", "nosmap", "nosmep", "emergency", "rescue", "-b", "_b", "rd.emergency",
    "rd.rescue", "2", "3", "4", "5", "nopti", "nospectre_v1", "nospectre_v2",
    "nospec_store_bypass_disable", "nospectre_bhb", "nokaslr",
]
for tok in FORMER_PREFIXES:
    for spelling in (tok, tok + "1"):
        if not refused_append(spelling):
            failures.append(f"--append {spelling!r} was accepted; the former denylist refused it")
for tok in FORMER_EXACT:
    if not refused_append(tok):
        failures.append(f"--append {tok!r} was accepted; the former denylist refused it")

# 3l. The allowlist. Anything not named is refused, so a spelling nobody
#     thought of (`mitigations=of`, which kstrtobool reads as off; `nopku`;
#     `spectre_v2_user=off`) fails closed. The three copies (executor.rs, this
#     helper, action-steps) must hold the same lists; this compares this helper
#     with executor.rs, and tests/release/action-steps.test.sh compares
#     action-steps with this helper and with executor.rs.
for tok in ["spectre-v2=off", "audit=off", "systemd.wants=debug-shell.service", "lsm=landlock",
            "mitigations=of", "nopku", "spectre_v2_user=off", "kpti=0", "its=off", "tsa=off",
            "vmscape=off", "noibrs", "noibpb", "audit=f", "foo=bar", "foo", "root=/dev/sdb1",
            "quiet=1", "console=", "lockdown=none", "mitigations=auto,nosmt,foo"]:
    if not refused_append(tok):
        failures.append(f"--append {tok!r} was accepted; it is not on the allowlist")
for tok in ["resume=/dev/sdb1", "resume_offset=1", "rd.driver.blacklist=tpm_crb",
            "rd.driver.blacklist=dm_crypt", "rd.driver.blacklist="]:
    if not refused_append(tok):
        failures.append(f"--append {tok!r} was accepted; resume= and non-GPU blacklists are not listed")
for tok in ["lockdown", "module.sig_enforce", "lockdown=integrity", "nosmt", "slab_nomerge",
            "vsyscall=none", "mitigations=auto", "foo=bar", "foo", "mitigations=of", "resume"]:
    if not refused(tok):
        failures.append(f"--delete {tok!r} was accepted; it is a hardening key or an unknown one")
for tok in ["quiet", "splash", "rhgb", "nomodeset", "nowatchdog", "threadirqs", "nosmt",
            "slab_nomerge", "console=ttyS0", "rd.driver.blacklist=nouveau",
            "transparent_hugepage=madvise", "lockdown=integrity", "lockdown=confidentiality",
            "module.sig_enforce=1", "intel_iommu=on", "amd_iommu=force_isolation", "init_on_alloc=1",
            "init_on_free=1", "page_alloc.shuffle=1", "randomize_kstack_offset=on",
            "mitigations=auto", "pti=on", "vsyscall=none", "debugfs=off"]:
    if refused_append(tok):
        failures.append(f"--append {tok!r} was refused, but it is on the allowlist")


def rust_list(const):
    decl = re.search(rf"const {const}:\s*&\[&str\]\s*=\s*&\[(.*?)\];", exec_src, re.S)
    return re.findall(r'"([^"]+)"', decl.group(1)) if decl else []


for const in ("KARG_FLAGS", "KARG_HARDENING_FLAGS", "KARG_VALUE_KEYS", "KARG_WEAKENING"):
    daemon = rust_list(const)
    if not daemon:
        failures.append(f"{const} not found or empty in executor.rs; compared nothing")
    elif sorted(daemon) != sorted(getattr(mod, const, ())):
        failures.append(f"{const} differs between executor.rs and this helper")
decl = re.search(r"const KARG_HARDENING_VALUES:\s*&\[\(&str, &\[&str\]\)\]\s*=\s*&\[(.*?)\n\];",
                 exec_src, re.S)
daemon_values = {k: sorted(re.findall(r'"([^"]+)"', v)) for k, v in
                 re.findall(r'\(\s*"([^"]+)",\s*&\[(.*?)\]\s*,?\s*\)', decl.group(1), re.S)} if decl else {}
if not daemon_values:
    failures.append("KARG_HARDENING_VALUES not found or empty in executor.rs; compared nothing")
elif daemon_values != {k: sorted(v) for k, v in getattr(mod, "KARG_HARDENING_VALUES", {}).items()}:
    failures.append("KARG_HARDENING_VALUES differs between executor.rs and this helper")
decl = re.search(r"const KARG_LIST_VALUES:\s*&\[\(&str, &\[&str\]\)\]\s*=\s*&\[(.*?)\]\s*;",
                 exec_src, re.S)
daemon_lists = {k: sorted(re.findall(r'"([^"]+)"', v)) for k, v in
                re.findall(r'\(\s*"([^"]+)",\s*&\[(.*?)\]\s*,?\s*\)', decl.group(1), re.S)} if decl else {}
if not daemon_lists:
    failures.append("KARG_LIST_VALUES not found or empty in executor.rs; compared nothing")
elif daemon_lists != {k: sorted(v) for k, v in getattr(mod, "KARG_LIST_VALUES", {}).items()}:
    failures.append("KARG_LIST_VALUES differs between executor.rs and this helper")

# 3f. A bare key deletes the key's only value. libostree's
#     ostree_kernel_args_delete removes `lockdown=confidentiality` when asked for
#     `lockdown`, and the prefix screen `lockdown=` never matched the bare key.
#     The daemon refuses these; a direct call must not get further.
for tok in ["lockdown", "module.sig_enforce", "selinux", "enforcing", "apparmor",
            "security", "iommu", "mitigations", "init_on_alloc", "lsm", "audit",
            "LOCKDOWN", "kaslr=1", "lsm=landlock,lockdown,yama", "audit=1"]:
    if not refused(tok):
        failures.append(f"--delete {tok!r} was accepted; it removes a boot protection")
for tok in ["mitigations=off", "selinux=0", "audit=0", "rhgb"]:
    if refused(tok):
        failures.append(f"--delete {tok!r} was refused, but removing it is safe")

# 3g. A root-shell unit pulled in with systemd.wants= is the same shell as
#     systemd.unit= makes the target, and these twins and switches weaken the boot
#     the way the tokens above them do.
for tok in ["systemd.wants=debug-shell.service", "rd.systemd.wants=emergency.target",
            "SYSTEMD.WANTS=Rescue.target", "lsm=landlock", "rd.shell", "rd.shell=1",
            "systemd.mask=auditd.service", "rd.systemd.mask=auditd.service",
            "modprobe.blacklist=apparmor", "audit=0", "nopti", "nospectre_v1",
            "nospectre_v2", "spectre_v2=off", "spec_store_bypass_disable=off", "nokaslr"]:
    if not refused_append(tok):
        failures.append(f"--append {tok!r} was accepted; it weakens the next boot")
for tok in ["systemd.wants=sshd.service", "audit=1", "spectre_v2=on"]:
    if not refused_append(tok):
        failures.append(f"--append {tok!r} was accepted; it is not on the allowlist")

# 3i. `-` and `_` are one character in a parameter NAME: the kernel's parameq()
#     (kernel/params.c) and systemd's proc_cmdline_key_streq() compare them as
#     equal. The screens normalise the key before matching, and every list entry
#     is written in that normal form, so a hyphen spelling of an entry cannot
#     exist in the lists and does not get through.
for tok in ["spectre-v2=off", "module-blacklist=apparmor", "Spec-Store-Bypass-Disable=off",
            "systemd.debug-shell=1", "rd.systemd.debug-shell", "nospectre-bhb", "nospectre-v2",
            "tsx-async-abort=off", "-b", "_b"]:
    if not refused_append(tok):
        failures.append(f"--append {tok!r} was accepted; `-` and `_` are equal in a parameter name")
for tok in ["module.sig-enforce=1", "init-on-alloc=1", "randomize-kstack-offset=on", "page-alloc.shuffle=1"]:
    if not refused(tok):
        failures.append(f"--delete {tok!r} was accepted; `-` and `_` are equal in a parameter name")
for tok in ["init-on-alloc=0", "module.sig-enforce=0"]:
    if refused(tok):
        failures.append(f"--delete {tok!r} was refused, but it is a weakening")
for attr in ("KARG_FLAGS", "KARG_HARDENING_FLAGS", "KARG_VALUE_KEYS", "KARG_WEAKENING",
             "KARG_HARDENING_VALUES", "KARG_LIST_VALUES"):
    if not getattr(mod, attr, ()):
        failures.append(f"{attr} is missing or empty; the normal-form check inspected nothing")
    for entry in getattr(mod, attr, ()):
        key = entry.split("=", 1)[0]
        if "-" in key or entry != entry.lower():
            failures.append(f"{attr} entry {entry!r} is not in normal form (lowercase, `_` in the key)")

# 3j. Every spelling of off for a switch the kernel reads as a boolean or as
#     `off`, and the remaining mitigation switches of kernel-parameters.txt.
for tok in ["audit=off", "audit=0", "audit=n", "audit=no", "audit=false", "AUDIT=OFF",
            "mitigations=false", "pti=no", "spectre_v2=n", "module.sig_enforce=no",
            "init_on_free=false", "mds=off", "tsx_async_abort=off", "mmio_stale_data=off",
            "retbleed=off", "srbds=off", "l1tf=off", "spectre_bhi=off",
            "gather_data_sampling=off", "reg_file_data_sampling=off",
            "nospec_store_bypass_disable", "nospectre_bhb"]:
    if not refused_append(tok):
        failures.append(f"--append {tok!r} was accepted; it switches a protection off")
for tok in ["mds=full", "retbleed=auto", "l1tf=flush", "spectre_bhi=on", "gather_data_sampling=force"]:
    if not refused_append(tok):
        failures.append(f"--append {tok!r} was accepted; it is not on the allowlist")
for tok in ["mds=full", "mds", "tsx_async_abort=full", "mmio_stale_data=full", "retbleed=auto",
            "srbds=on", "l1tf=flush", "spectre_bhi=on", "gather_data_sampling=force",
            "reg_file_data_sampling=on", "spectre_v2=on", "spec_store_bypass_disable=on"]:
    if not refused(tok):
        failures.append(f"--delete {tok!r} was accepted; it removes a mitigation")
for tok in ["mds=off", "retbleed=off", "spectre_v2=off"]:
    if refused(tok):
        failures.append(f"--delete {tok!r} was refused, but it is a weakening")
# Only the spellings in KARG_WEAKENING are known downgrades; any other key is refused.
for tok in ["audit=false", "pti=no"]:
    if not refused(tok):
        failures.append(f"--delete {tok!r} was accepted; it is not in KARG_WEAKENING")

# 3d. Ordinary appends must survive, or the screen has eaten the feature.
for tok in ["quiet", "splash", "nomodeset", "console=ttyS0", "transparent_hugepage=madvise"]:
    if refused_append(tok):
        failures.append(f"--append {tok!r} was refused, but it carries no security meaning")

# 3e. PARITY with the daemon's own list, derived rather than restated.
#     The helper's header says it enforces the same policy independently
#     because it is directly sudo-invocable through the wildcard grant. It
#     held ("emergency", "rescue", "single") while the daemon's
#     ROOT_SHELL_UNITS held five, so `systemd.unit=debug-shell.service` and
#     `systemd.unit=runlevel1.target` reached the boot line through a direct
#     call. systemd-debug-generator then pulls debug-shell.service into the
#     boot transaction, which is a root shell on tty9 with no login prompt,
#     persisting across reboots, with no preview, no approval receipt and no
#     row in the signed chain.
#
#     Reading the daemon's list out of its source is the point. A copy of it
#     here would drift exactly the way the helper drifted.
validate_rs = os.path.join(repo_root, "crates/sysknife-daemon/src/actions/validate.rs")
try:
    rust_src = open(validate_rs, encoding="utf-8").read()
except OSError as exc:
    failures.append(f"cannot read {validate_rs}: {exc}; the parity check inspected nothing")
    rust_src = ""
decl = re.search(r"ROOT_SHELL_UNITS:\s*&\[&str\]\s*=\s*&\[(.*?)\];", rust_src, re.S)
if decl is None:
    failures.append(
        "ROOT_SHELL_UNITS not found in validate.rs; this check would pass over an "
        "empty set, so it fails instead")
else:
    daemon_units = set(re.findall(r'"([^"]+)"', decl.group(1)))
    if not daemon_units:
        failures.append("ROOT_SHELL_UNITS parsed as empty; refusing to compare against nothing")
    # The allowlist names no systemd.unit= at all; prove each unit is refused.
    for unit in sorted(daemon_units):
        for spelling in (f"systemd.unit={unit}.service", f"systemd.unit={unit}.target"):
            if not refused_append(spelling):
                failures.append(f"--append {spelling!r} was accepted; it yields a root shell")

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
