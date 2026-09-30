#!/usr/bin/env bash
# Guards sysknife-fail2ban-ban, which replaced a `fail2ban-client set *` sudoers
# wildcard.
#
# The grant that authorised Fail2banBanIp used to be:
#
#   sysknife ALL=(root) NOPASSWD: /usr/bin/fail2ban-client set *
#
# and the comment above it already named the problem: `fail2ban-client set
# <jail> action <name> actionban <cmd>` runs <cmd> as root. Narrowing to
# `set * banip *` does not fix it, because sudo's `*` matches across spaces and
# the variable jail name sits before the fixed `banip` token, which sudoers
# cannot pin. The helper's argv is fixed instead.
#
# The helper is callable directly through its own trailing-wildcard grant, which
# skips the preview, the receipt and the signed chain, so the screen below is the
# only guard on that path and these are the tests of it.
#
# Pure-function test: no root, no fail2ban, no subprocess.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/packaging/sysknife-fail2ban-ban"

[ -f "$SCRIPT" ] || { echo "FAIL: $SCRIPT not found"; exit 1; }

python3 - "$SCRIPT" <<'PY'
import importlib.util
import os
import re
import sys
from importlib.machinery import SourceFileLoader

script_path = sys.argv[1]
loader = SourceFileLoader("fail2ban_ban", script_path)
spec = importlib.util.spec_from_loader("fail2ban_ban", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

failures = []


def refused(fn, value):
    try:
        fn(value)
    except SystemExit as exc:
        return exc.code != 0
    return False


# 1. Jail names. The accept list carries the two spellings that made the first
#    draft of this helper stricter than the daemon: a leading `_` and a leading
#    `.` are allowed by jail_is_valid, and refusing them here would be a grant
#    that works through the daemon and fails through the helper.
for jail in ["sshd", "_foo", ".foo", "a-b_c.d", "A1", "a" * 64]:
    if refused(mod.validated_jail, jail):
        failures.append(f"jail {jail!r} is valid for the daemon and was refused here")
for jail in ["-foo", "", "a" * 65, "foo bar", "foo/bar", "foo;id", "foo$(id)", "ünicode",
             "foo\nbar"]:
    if not refused(mod.validated_jail, jail):
        failures.append(f"jail {jail!r} was accepted")

# 2. Addresses. One address at a time: a CIDR or a range would ban more than the
#    approved preview named.
for ip in ["192.0.2.1", "203.0.113.7", "::1", "2001:db8::1"]:
    if refused(mod.validated_ip, ip):
        failures.append(f"{ip!r} is a valid address and was refused")
for ip in ["192.0.2.0/24", "192.0.2.1-192.0.2.9", "example.com", "", "192.0.2.256",
           "192.0.2.1 banip", "-1"]:
    if not refused(mod.validated_ip, ip):
        failures.append(f"{ip!r} was accepted as an address")

# 3. The argv is fixed. Nothing the caller supplies reaches fail2ban-client as a
#    subcommand, which is the whole reason this helper exists.
recorded = {}


class Completed:
    returncode = 0


def fake_run(argv, **kwargs):
    recorded["argv"] = list(argv)
    recorded["kwargs"] = kwargs
    return Completed()


mod.subprocess.run = fake_run
argv_backup = sys.argv[:]
try:
    for op, verb in (("ban", "banip"), ("unban", "unbanip")):
        recorded.clear()
        sys.argv = ["sysknife-fail2ban-ban", "--op", op, "--jail", "sshd", "--ip", "192.0.2.1"]
        rc = mod.main()
        if rc != 0:
            failures.append(f"--op {op} returned {rc} on a clean run")
        want = [mod.FAIL2BAN_CLIENT, "set", "sshd", verb, "192.0.2.1"]
        if recorded.get("argv") != want:
            failures.append(f"--op {op} built {recorded.get('argv')!r}, expected {want!r}")
        if recorded.get("kwargs", {}).get("shell"):
            failures.append(f"--op {op} ran through a shell")

    # 3b. An --op the helper does not know must not reach fail2ban-client.
    for bad_op in ["action", "addaction", "banip", "set", "--", "ban;id"]:
        recorded.clear()
        sys.argv = ["sysknife-fail2ban-ban", "--op", bad_op, "--jail", "sshd",
                    "--ip", "192.0.2.1"]
        try:
            mod.main()
        except SystemExit as exc:
            if exc.code == 0:
                failures.append(f"--op {bad_op!r} exited 0")
        else:
            failures.append(f"--op {bad_op!r} was accepted")
        if recorded.get("argv"):
            failures.append(f"--op {bad_op!r} reached fail2ban-client as {recorded['argv']!r}")

    # 4. A failed ban must not report success. A helper that exits 0 over a
    #    failed ban tells the daemon, the audit chain and the operator that a
    #    host is protected when it is not.
    class Failed:
        returncode = 7

    mod.subprocess.run = lambda argv, **kw: Failed()
    sys.argv = ["sysknife-fail2ban-ban", "--op", "ban", "--jail", "sshd", "--ip", "192.0.2.1"]
    rc = mod.main()
    if rc != 7:
        failures.append(f"a fail2ban-client exit of 7 was reported as {rc}")
finally:
    sys.argv = argv_backup

# 5. CANARY on the daemon's rule. jail_is_valid is a function rather than a
#    constant, so there is nothing to parse and compare. Pin the character class
#    instead: an edit there is a signal to review the regex in this helper.
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(script_path)))
fail2ban_rs = os.path.join(repo_root, "crates/sysknife-daemon/src/actions/fail2ban.rs")
try:
    rust_src = open(fail2ban_rs, encoding="utf-8").read()
except OSError as exc:
    failures.append(f"cannot read {fail2ban_rs}: {exc}; the canary inspected nothing")
    rust_src = ""
body = re.search(r"fn jail_is_valid\(jail: &str\) -> bool \{(.*?)\n\}", rust_src, re.S)
if body is None:
    failures.append(
        "jail_is_valid not found in fail2ban.rs; the canary would pass over nothing, so it "
        "fails instead")
else:
    expected = [
        ("length cap", "jail.len() > 64"),
        ("leading dash", 'jail.starts_with(\'-\')'),
        ("character class", "matches!(c, '_' | '-' | '.')"),
    ]
    for what, needle in expected:
        if needle not in body.group(1):
            failures.append(
                f"jail_is_valid no longer contains its {what} ({needle!r}); JAIL_RE in "
                "packaging/sysknife-fail2ban-ban was transcribed from it and needs review")

if failures:
    for f in failures:
        print(f"FAIL: {f}")
    sys.exit(1)

print("ok: sysknife-fail2ban-ban builds a fixed argv and agrees with the daemon on jail names")
PY
