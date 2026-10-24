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
import io
import os
import sys
import tempfile
from importlib.machinery import SourceFileLoader
from unittest import mock

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

pristine_load_path = tuple(getattr(mod, "UNIT_LOAD_PATH", ()))
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
    real_stderr = sys.stderr
    sys.stderr = captured = io.StringIO()
    try:
        mod.main()
        return 0
    except SystemExit as exc:
        return int(exc.code or 0)
    finally:
        sys.stderr = real_stderr
        invoke.stderr = captured.getvalue()
        real_stderr.write(invoke.stderr)

try:
    # Exact reproducer requested in #484: an existing legacy/unprefixed
    # ssh.service must survive byte-for-byte and the ambiguous job name is
    # refused. This is RED on the vulnerable implementation because it opens
    # ssh.service with "w" and truncates it.
    with tempfile.TemporaryDirectory() as root:
        mod.UNIT_DIR = root
        mod.UNIT_LOAD_PATH = (root,)
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
        mod.UNIT_LOAD_PATH = (root,)
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
        mod.UNIT_LOAD_PATH = (root,)
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

    # The same two collisions when the unit appears between the load-path check
    # and the create. The check above now refuses both cases first, so without
    # hiding the file from it these would no longer reach O_EXCL and its
    # rollback at all.
    for unit, job in [("sysknife-race.service", "race"), ("sysknife-race.timer", "race")]:
        with tempfile.TemporaryDirectory() as root:
            mod.UNIT_DIR = root
            mod.UNIT_LOAD_PATH = (root,)
            target = os.path.join(root, unit)
            with open(target, "wb") as fh:
                fh.write(b"appeared late\n")
            with mock.patch.object(mod.os.path, "lexists", return_value=False):
                code = invoke(job)
            if code == 0:
                failures.append(f"{unit} created after the check did not make the helper fail")
            if open(target, "rb").read() != b"appeared late\n":
                failures.append(f"{unit} created after the check was modified")
            if sorted(os.listdir(root)) != [unit]:
                failures.append(
                    f"a race on {unit} left {sorted(os.listdir(root))}; the pair must be "
                    "all-or-nothing")

    # The rest of systemd's unit load path. A unit in UNIT_DIR overrides one of
    # the same name further down, so a job named `daemon` used to write
    # /etc/systemd/system/sysknife-daemon.service over the packaged daemon unit
    # in /usr/lib/systemd/system, as a root oneshot with a caller-chosen
    # ExecStart. Both stems, legacy and namespaced, in every directory.
    want_path = {"/etc/systemd/system", "/run/systemd/system",
                 "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
                 "/lib/systemd/system"}
    if set(pristine_load_path) != want_path:
        failures.append(
            f"UNIT_LOAD_PATH is {sorted(pristine_load_path)}, expected {sorted(want_path)}")
    for unit, job in [("sysknife-daemon.service", "daemon"),
                      ("sysknife-backup.timer", "backup"),
                      ("ssh.service", "ssh"),
                      ("fstrim.timer", "fstrim")]:
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as vendor:
            mod.UNIT_DIR = root
            mod.UNIT_LOAD_PATH = (root, vendor)
            with open(os.path.join(vendor, unit), "wb") as fh:
                fh.write(b"[Unit]\nDescription=packaged unit\n")
            code = invoke(job)
            if code == 0:
                failures.append(
                    f"job {job!r} was created over {unit} in another load-path directory")
            elif vendor not in invoke.stderr:
                failures.append(
                    f"refusal for job {job!r} does not name {vendor}: {invoke.stderr!r}")
            if os.listdir(root):
                failures.append(f"job {job!r} left {sorted(os.listdir(root))} in UNIT_DIR")

    # Clean creation uses the namespace consistently, including systemctl.
    with tempfile.TemporaryDirectory() as root:
        mod.UNIT_DIR = root
        mod.UNIT_LOAD_PATH = (root,)
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
