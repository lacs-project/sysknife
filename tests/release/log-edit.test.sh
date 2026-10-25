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

# 4. A bare wildcard over the log root, the audit directory or the journal,
#    and `rotate 0` over any wildcard, let a Dev-tier caller have root's
#    logrotate delete the host's evidence (GHSA-68v6-p23h-fwcf). The daemon
#    refuses both; this helper is reachable directly through its wildcard grant,
#    so it refuses them too, before writing anything.
def refused(path, rotate):
    args = Args(path)
    args.rotate = rotate
    wrote["path"] = None
    mod.atomic_write = fake_atomic_write
    mod.subprocess.run = lambda *a, **k: FakeCompleted()
    try:
        mod.op_logrotate(args)
        return False
    except SystemExit as exc:
        return exc.code != 0 and wrote["path"] is None
    finally:
        mod.atomic_write = real_atomic_write
        mod.subprocess.run = real_run


import re
from pathlib import Path
rust = Path(script_path).resolve().parents[1].joinpath(
    "crates/sysknife-daemon/src/actions/validate.rs").read_text(encoding="utf-8")
decl = re.search(r"LOG_EVIDENCE_DIRS:\s*&\[&str\]\s*=\s*&\[(.*?)\];", rust, re.S)
daemon_dirs = set(re.findall(r'"([^"]+)"', decl.group(1))) if decl else set()
if not daemon_dirs:
    failures.append("LOG_EVIDENCE_DIRS not found in validate.rs; parity checked nothing")
elif not daemon_dirs <= set(getattr(mod, "LOG_EVIDENCE_DIRS", ())):
    failures.append(f"helper LOG_EVIDENCE_DIRS is missing {sorted(daemon_dirs - set(mod.LOG_EVIDENCE_DIRS))}")

for p in ["/var/log/*", "/var/log/**", "/var/log/audit/*", "/var/log/journal/*",
          "/var/log//audit/*", "/var/log/./audit/*", "/var/log/audit/./*",
          "/var/log/*/*", "/var/log/journal/*/*"]:
    if not refused(p, 7):
        failures.append(f"{p!r} sweeps the log evidence but was accepted")
for p in ["/var/log/nginx/*.log", "/var/log/myapp/*"]:
    if not refused(p, 0):
        failures.append(f"rotate 0 over {p!r} was accepted")
for p, rotate in [("/var/log/nginx/*.log", 7), ("/var/log/myapp/*", 1),
                  ("/var/log/app.log", 0), ("/var/log/audit/audit.log", 5)]:
    if refused(p, rotate):
        failures.append(f"{p!r} rotate {rotate} is ordinary but was refused")

if failures:
    for f in failures:
        print("FAIL:", f)
    sys.exit(1)
print("ok: sysknife-log-edit confines rotation targets to the log root")
print("ok: op_logrotate refuses an out-of-root path before writing a config")
print("ok: op_logrotate refuses a wildcard sweep of the log evidence and rotate 0 over a glob")
PY
