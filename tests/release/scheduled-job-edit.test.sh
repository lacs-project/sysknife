#!/usr/bin/env bash
# Regression coverage for CreateScheduledJob unit-name collisions (#484).
# The helper must never overwrite an existing systemd unit, must namespace new
# units as sysknife-<name>, and must not leave half of a service/timer pair behind.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/packaging/sysknife-scheduled-job-edit"

[ -f "$SCRIPT" ] || { echo "FAIL: $SCRIPT not found"; exit 1; }

if [ -n "${PYTHON:-}" ]; then
  :
elif command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON=python
else
  echo "FAIL: python is required"
  exit 1
fi

"$PYTHON" - "$SCRIPT" <<'PY'
import importlib.util
import os
import sys
import tempfile
from importlib.machinery import SourceFileLoader

script_path = sys.argv[1]
loader = SourceFileLoader("scheduled_job_edit", script_path)
spec = importlib.util.spec_from_loader("scheduled_job_edit", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

class Completed:
    returncode = 0

calls = []

def fake_run(cmd, **kwargs):
    calls.append(list(cmd))
    return Completed()

real_run = mod.subprocess.run
real_argv = sys.argv[:]
mod.subprocess.run = fake_run

failures = []

def invoke(name):
    sys.argv = [
        script_path,
        "--name", name,
        "--command", "/usr/bin/true",
        "--schedule", "daily",
    ]
    try:
        mod.main()
        return 0
    except SystemExit as exc:
        return int(exc.code or 0)

try:
    # Exact reproducer requested in #484: an existing legacy/unprefixed
    # ssh.service must survive byte-for-byte and the ambiguous job name is
    # refused. This is RED on the vulnerable implementation because it opens
    # ssh.service with "w" and truncates it.
    with tempfile.TemporaryDirectory() as root:
        mod.UNIT_DIR = root
        legacy = os.path.join(root, "ssh.service")
        original = b"[Unit]\nDescription=real ssh service\n"
        with open(legacy, "wb") as fh:
            fh.write(original)

        code = invoke("ssh")
        if code == 0:
            failures.append("existing legacy ssh.service did not make the helper fail")
        if open(legacy, "rb").read() != original:
            failures.append("existing legacy ssh.service was modified")
        if os.path.exists(os.path.join(root, "sysknife-ssh.service")):
            failures.append("helper created a namespaced service despite legacy-name collision")

    # Collision at the new namespaced service path must be refused atomically.
    with tempfile.TemporaryDirectory() as root:
        mod.UNIT_DIR = root
        target = os.path.join(root, "sysknife-backup.service")
        original = b"keep me\n"
        with open(target, "wb") as fh:
            fh.write(original)

        code = invoke("backup")
        if code == 0:
            failures.append("existing sysknife-backup.service did not make the helper fail")
        if open(target, "rb").read() != original:
            failures.append("existing sysknife-backup.service was modified")
        if os.path.exists(os.path.join(root, "sysknife-backup.timer")):
            failures.append("timer was created after service-path collision")

    # If the service was created but the timer path collides, clean up the
    # just-created service so the pair is all-or-nothing.
    with tempfile.TemporaryDirectory() as root:
        mod.UNIT_DIR = root
        timer = os.path.join(root, "sysknife-nightly.timer")
        original = b"existing timer\n"
        with open(timer, "wb") as fh:
            fh.write(original)

        code = invoke("nightly")
        if code == 0:
            failures.append("existing sysknife-nightly.timer did not make the helper fail")
        if open(timer, "rb").read() != original:
            failures.append("existing sysknife-nightly.timer was modified")
        if os.path.exists(os.path.join(root, "sysknife-nightly.service")):
            failures.append("service was left behind after timer-path collision")

    # Clean creation uses the namespace consistently, including systemctl.
    with tempfile.TemporaryDirectory() as root:
        mod.UNIT_DIR = root
        calls.clear()
        code = invoke("clean")
        if code != 0:
            failures.append(f"clean namespaced creation failed with exit {code}")
        service = os.path.join(root, "sysknife-clean.service")
        timer = os.path.join(root, "sysknife-clean.timer")
        if not os.path.isfile(service):
            failures.append("sysknife-clean.service was not created")
        if not os.path.isfile(timer):
            failures.append("sysknife-clean.timer was not created")
        if os.path.exists(os.path.join(root, "clean.service")):
            failures.append("unprefixed clean.service was created")
        if os.path.exists(os.path.join(root, "clean.timer")):
            failures.append("unprefixed clean.timer was created")
        expected_enable = [mod.SYSTEMCTL, "enable", "--now", "sysknife-clean.timer"]
        if expected_enable not in calls:
            failures.append(f"systemctl did not enable namespaced timer: calls={calls!r}")
finally:
    mod.subprocess.run = real_run
    sys.argv = real_argv

if failures:
    for failure in failures:
        print("FAIL:", failure)
    sys.exit(1)

print("ok: scheduled-job helper refuses legacy and namespaced collisions")
print("ok: scheduled-job helper creates only sysknife-<name> unit pairs")
print("ok: timer collision does not leave an orphan service")
PY
