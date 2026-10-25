#!/usr/bin/env bash
# Guards every packaging/ helper's input screen against a trailing newline.
#
# The helpers validated with `re.compile(r"^...$")` and `.match()`. In Python
# `$` also matches just before a trailing newline, so `bash\n` passed the
# character-class check, missed every exact-membership denylist that followed,
# and reached the file the helper writes (GHSA-3448-xjpf-cc4j). The Rust twins
# check characters one by one and refuse the newline, so only the direct sudo
# path was open, and on that path the helper's screen is the only guard.
#
# Each case below drives a helper's main() twice with every side effect stubbed:
# once with valid arguments, which must get past the screen (the positive
# control, proving the case stands in front of the guard), and once per
# free-text argument with a newline appended, which must exit non-zero before
# any side effect runs. A helper that goes back to `.match` fails here.
#
# In-process test: no root, no writes, no subprocess.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

python3 - "$ROOT/packaging" <<'PY'
import builtins
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from importlib.machinery import SourceFileLoader
from unittest import mock

packaging = sys.argv[1]

# (helper, valid argv, the arguments that carry caller text)
CASES = [
    ("sysknife-apt-pin-edit",
     ["--op", "set", "--name", "web", "--package", "nginx", "--pin", "release a=noble",
      "--priority", "500"],
     ["--name", "--package", "--pin"]),
    ("sysknife-apt-pin-edit", ["--op", "remove", "--name", "web"], ["--name"]),
    ("sysknife-audit-edit",
     ["--op", "add", "--key", "passwd-watch", "--path", "/etc/passwd", "--perms", "wa"],
     ["--key", "--path", "--perms"]),
    ("sysknife-audit-edit", ["--op", "remove", "--key", "passwd-watch"], ["--key"]),
    ("sysknife-fail2ban-ban", ["--op", "ban", "--jail", "sshd", "--ip", "192.0.2.1"],
     ["--jail", "--ip"]),
    ("sysknife-fail2ban-jail-edit", ["--name", "sshd", "--maxretry", "5"], ["--name"]),
    ("sysknife-grub-kargs-edit", ["--append", "quiet"], ["--append"]),
    ("sysknife-grub-kargs-edit", ["--delete", "quiet"], ["--delete"]),
    ("sysknife-log-edit",
     ["--op", "logrotate", "--name", "app", "--path", "/var/log/app.log",
      "--frequency", "daily", "--rotate", "7"],
     ["--name", "--path"]),
    ("sysknife-log-edit", ["--op", "rm-logrotate", "--name", "app"], ["--name"]),
    ("sysknife-log-edit",
     ["--op", "rsyslog-forward", "--host", "logs.example.com", "--port", "514",
      "--protocol", "tcp"],
     ["--host"]),
    ("sysknife-mount-edit",
     ["--op", "mount", "--device", "/dev/sdb1", "--mountpoint", "/mnt/data",
      "--fstype", "ext4", "--options", "rw"],
     ["--device", "--mountpoint", "--options"]),
    ("sysknife-mount-edit", ["--op", "unmount", "--mountpoint", "/mnt/data"], ["--mountpoint"]),
    ("sysknife-mount-edit", ["--op", "addswap", "--file", "/swapfile2", "--size-mb", "64"],
     ["--file"]),
    ("sysknife-mount-edit", ["--op", "rmswap", "--file", "/swapfile2"], ["--file"]),
    ("sysknife-scheduled-job-edit",
     ["--name", "backup", "--command", "/usr/bin/true", "--schedule", "daily"],
     ["--name", "--command", "--schedule"]),
    ("sysknife-sudoers-edit",
     ["--op", "grant", "--name", "deploy", "--user", "deploy", "--runas", "root",
      "--commands", "/usr/bin/uptime", "--nopasswd"],
     ["--name", "--user", "--runas", "--commands"]),
    ("sysknife-sudoers-edit", ["--op", "revoke", "--name", "deploy"], ["--name"]),
    ("sysknife-sysctl-edit", ["--key", "net.ipv4.ip_forward", "--value", "1"],
     ["--key", "--value"]),
]


class Reached(Exception):
    """A side effect ran: the screen let the input through."""


SIDE_EFFECTS = [
    (builtins, "open"),
    (os, "open"), (os, "makedirs"), (os, "mkdir"), (os, "unlink"), (os, "remove"),
    (os, "replace"), (os, "rename"), (os, "chmod"), (os, "execve"),
    (tempfile, "mkstemp"), (shutil, "copy2"),
    (subprocess, "run"), (subprocess, "Popen"), (subprocess, "call"),
    (subprocess, "check_call"), (subprocess, "check_output"),
]


def load(helper):
    path = os.path.join(packaging, helper)
    name = helper.replace("-", "_")
    loader = SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def outcome(helper, argv):
    """'refused', 'reached' or 'returned' for one run of the helper's main()."""
    mod = load(helper)
    patches = []
    for owner, attr in SIDE_EFFECTS:
        def stub(*_a, _what=f"{owner.__name__}.{attr}", **_k):
            raise Reached(_what)
        patches.append(mock.patch.object(owner, attr, stub))
    saved_argv, saved_stderr = sys.argv, sys.stderr
    sys.argv = [helper, *argv]
    sys.stderr = open(os.devnull, "w")
    try:
        for p in patches:
            p.start()
        try:
            mod.main()
        except SystemExit as exc:
            return "returned" if exc.code in (0, None) else "refused"
        except Reached:
            return "reached"
        return "returned"
    finally:
        for p in reversed(patches):
            p.stop()
        sys.stderr.close()
        sys.argv, sys.stderr = saved_argv, saved_stderr


failures = []
covered = set()
checked = 0
for helper, argv, fields in CASES:
    covered.add(helper)
    control = outcome(helper, argv)
    if control == "refused":
        failures.append(
            f"{helper} {argv!r} was refused with valid input; the newline cases below "
            "would pass for the wrong reason")
        continue
    for field in fields:
        i = argv.index(field) + 1
        bad = argv[:i] + [argv[i] + "\n"] + argv[i + 1:]
        got = outcome(helper, bad)
        checked += 1
        if got != "refused":
            failures.append(
                f"{helper}: {field} {argv[i] + chr(10)!r} was not refused ({got}); "
                "a `$`-anchored .match() lets a trailing newline through")

# Every helper that screens with a compiled regex must have a case here, so a
# new helper cannot arrive without this check.
for name in sorted(os.listdir(packaging)):
    path = os.path.join(packaging, name)
    try:
        src = open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        continue
    if src.startswith("#!") and "python" in src.splitlines()[0] and "re.compile(" in src:
        if name not in covered:
            failures.append(f"{name} screens with a compiled regex and has no case here")

if checked == 0:
    failures.append("no newline case ran; this test checked nothing")

if failures:
    for f in failures:
        print(f"FAIL: {f}")
    sys.exit(1)
print(f"ok: {checked} newline-suffixed inputs refused across {len(covered)} helpers")
PY
