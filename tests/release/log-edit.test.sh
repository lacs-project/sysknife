#!/usr/bin/env bash
# Guards sysknife-log-edit against the arbitrary-rotation-target class.
#
# `--path` becomes the stanza header of a config that root's logrotate acts on,
# so an unconfined path turns a Medium-risk action into "truncate, rename, or
# delete any file on the box, as root, on a timer". The charset regex alone does
# not stop `/etc/shadow` or `/boot/*` — only a root-directory confinement does.
# Pure-function test: no root, no real logrotate, no writes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/packaging/sysknife-log-edit"

[ -f "$SCRIPT" ] || { echo "FAIL: $SCRIPT not found"; exit 1; }

python3 - "$SCRIPT" <<'PY'
import importlib.util
import sys
from importlib.machinery import SourceFileLoader

script_path = sys.argv[1]
# The script has no .py suffix, so name a SourceFileLoader explicitly.
loader = SourceFileLoader("log_edit", script_path)
spec = importlib.util.spec_from_loader("log_edit", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

failures = []

guard = getattr(mod, "valid_log_glob", None)
if guard is None:
    print("FAIL: valid_log_glob() missing from sysknife-log-edit")
    sys.exit(1)

# 1. Paths outside the log root are refused, however well-formed.
OUTSIDE = [
    "/etc/shadow",
    "/etc/*",
    "/boot/*",
    "/root/.ssh/authorized_keys",
    "/home/*/.bashrc",
    "/usr/lib/sysknife/*",
    "/*",
    "/",
    "/var/lib/*",          # adjacent to the log root but not under it
    "/var/logs/x",         # prefix-of-a-prefix: must not pass on a bare match
    "/var/log",            # the directory itself, not a file under it
    "//var/log/x",         # doubled slash must not launder the prefix
    "/var/log/../etc/*",   # traversal
]
for p in OUTSIDE:
    if guard(p):
        failures.append(f"{p!r} was accepted as a rotation target")

# 2. Genuine log globs still work — the guard must not break the action.
INSIDE = [
    "/var/log/nginx/*.log",
    "/var/log/syslog",
    "/var/log/myapp/current.log",
    "/var/log/a-b_c.1.log",
]
for p in INSIDE:
    if not guard(p):
        failures.append(f"{p!r} is a legitimate log glob but was refused")


# 3. WIRING: op_logrotate must consult the guard BEFORE writing anything.
#    atomic_write and subprocess.run are replaced so a removed guard writes into
#    the fake and fails this test, rather than dropping a real root-run config.
class Args:
    def __init__(self, path):
        self.name = "probe"
        self.path = path
        self.frequency = "daily"
        self.rotate = 7
        self.compress = False


wrote = {"path": None}
real_atomic_write = mod.atomic_write
real_run = mod.subprocess.run


def fake_atomic_write(path, content, mode=0o644):
    wrote["path"] = path


class FakeCompleted:
    returncode = 0
    stderr = b""


mod.atomic_write = fake_atomic_write
mod.subprocess.run = lambda *a, **k: FakeCompleted()
try:
    try:
        mod.op_logrotate(Args("/etc/shadow"))
        failures.append("op_logrotate did NOT refuse '/etc/shadow'")
    except SystemExit as exc:
        if exc.code == 0:
            failures.append("op_logrotate exited 0 on '/etc/shadow'")
    if wrote["path"] is not None:
        failures.append(f"op_logrotate wrote {wrote['path']!r} before refusing the path")
finally:
    mod.atomic_write = real_atomic_write
    mod.subprocess.run = real_run

if failures:
    for f in failures:
        print("FAIL:", f)
    sys.exit(1)
print("ok: sysknife-log-edit confines rotation targets to the log root")
print("ok: op_logrotate refuses an out-of-root path before writing a config")
PY
