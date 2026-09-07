#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
recorder="$repo_root/scripts/record_test_baseline.py"
checker="$repo_root/scripts/check_evidence_claims.py"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

rust_count="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['tests'])" \
    "$repo_root/tests/evidence/workspace-tests.json")"
frontend_count="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['frontend_tests'])" \
    "$repo_root/tests/evidence/workspace-tests.json")"

record() {
    python3 "$recorder" \
        --artifact "$1" \
        --field "$2" \
        --count "$3"
}

# The pristine artifact must still pass the full evidence checker; its live suite
# gates remain independent from this schema contract.
python3 "$checker" "$repo_root" >/dev/null

artifact="$fixture/workspace-tests.json"
record "$artifact" tests "$rust_count"
record "$artifact" frontend_tests "$frontend_count"

python3 - "$artifact" "$recorder" "$checker" <<'PY'
import importlib.util
import json
import shutil
import sys
from pathlib import Path

artifact_path, recorder_path, checker_path = sys.argv[1:]
document = json.loads(open(artifact_path, encoding="utf-8").read())
expected_keys = {"commands", "frontend_tests", "tests", "version"}
if set(document) != expected_keys:
    raise SystemExit(
        f"generated artifact has {sorted(document)}, expected {sorted(expected_keys)}"
    )
if document["version"] != 2:
    raise SystemExit(f"generated artifact has schema version {document['version']}, expected 2")

spec = importlib.util.spec_from_file_location("record_test_baseline", recorder_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
if not hasattr(module, "validate_document"):
    raise SystemExit("record_test_baseline.py must expose the schema validator")

problems = module.validate_document(document, require_all_fields=True)
if problems:
    raise SystemExit("generated artifact was rejected: " + "; ".join(problems))
if document["commands"] != module.COMMANDS:
    raise SystemExit(
        f"generated artifact commands {document['commands']!r} do not match "
        f"the canonical commands {module.COMMANDS!r}"
    )

for field in ("tests", "frontend_tests"):
    command_edit = dict(document)
    command_edit["commands"] = dict(document["commands"])
    command_edit["commands"][field] += " --altered"
    problems = module.validate_document(command_edit, require_all_fields=True)
    if not problems or not any(f"commands['{field}']" in problem for problem in problems):
        raise SystemExit(f"altered {field} command was not rejected")

# A count-only artifact remains valid if its expected number changes. The live
# runner gate, not this schema check, decides whether that number is true.
count_edit = dict(document)
count_edit["tests"] += 1
if module.validate_document(count_edit, require_all_fields=True):
    raise SystemExit("schema validation must not reject a count solely because it changed")

# Old-looking metadata is the false provenance this issue is about. It must not
# survive as an authoritative-looking extension to the count-only contract.
metadata_edit = dict(document)
metadata_edit["commit"] = {"tests": "a" * 40}
metadata_edit["measured_at"] = {"tests": "2026-09-07T00:00:00Z"}
problems = module.validate_document(metadata_edit, require_all_fields=True)
if not problems or not any("unsupported top-level fields" in problem for problem in problems):
    raise SystemExit("hand-edited provenance metadata was not rejected")

checker_spec = importlib.util.spec_from_file_location("check_evidence_claims", checker_path)
checker_module = importlib.util.module_from_spec(checker_spec)
checker_spec.loader.exec_module(checker_module)
checker_root = Path(artifact_path).parent / "checker-root"
checker_artifact = checker_root / "tests" / "evidence" / "workspace-tests.json"
checker_artifact.parent.mkdir(parents=True)
shutil.copyfile(artifact_path, checker_artifact)
checker_module.load_test_baseline(checker_root)
checker_artifact.write_text(json.dumps(metadata_edit), encoding="utf-8")
try:
    checker_module.load_test_baseline(checker_root)
except checker_module.Failure:
    pass
else:
    raise SystemExit("evidence checker accepted hand-edited provenance metadata")

for label, version in (("legacy", 1), ("future", 3)):
    version_edit = dict(document)
    version_edit["version"] = version
    problems = module.validate_document(version_edit, require_all_fields=True)
    if not problems or not any("version" in problem for problem in problems):
        raise SystemExit(f"{label} schema version was not rejected")

malformed = dict(document)
malformed["tests"] = True
problems = module.validate_document(malformed, require_all_fields=True)
if not problems or not any("tests" in problem for problem in problems):
    raise SystemExit("boolean test count was not rejected")
PY

# Exercise the actual wrapper's count gate with isolated runners. This keeps the
# live-suite proof intact without requiring the Rust or Node toolchains here.
fake_bin="$fixture/fake-bin"
sandbox="$fixture/baseline-root"
mkdir -p "$fake_bin" "$sandbox/scripts" "$sandbox/tests/evidence" \
    "$sandbox/apps/sysknife-shell/node_modules/.bin"
cp "$repo_root/scripts/test_baseline.sh" "$sandbox/scripts/test_baseline.sh"
cp "$recorder" "$sandbox/scripts/record_test_baseline.py"
cp "$repo_root/tests/evidence/workspace-tests.json" \
    "$sandbox/tests/evidence/workspace-tests.json"
python3 - "$fake_bin/cargo" "$fake_bin/vitest" <<'PY'
import os
import sys
from pathlib import Path

cargo_path, vitest_path = map(Path, sys.argv[1:])
cargo_path.write_text(
    r'''#!/usr/bin/env bash
printf 'Starting %s tests across 1 binaries\n' "${FAKE_RUST_COUNT:-0}"
exit "${FAKE_RUST_STATUS:-0}"
''',
    encoding="utf-8",
)
vitest_path.write_text(
    r'''#!/usr/bin/env bash
printf 'Tests  %s passed (%s)\n' "${FAKE_FRONTEND_COUNT:-0}" "${FAKE_FRONTEND_COUNT:-0}"
exit "${FAKE_FRONTEND_STATUS:-0}"
''',
    encoding="utf-8",
)
for path in (cargo_path, vitest_path):
    os.chmod(path, 0o755)
PY
cp "$fake_bin/vitest" "$sandbox/apps/sysknife-shell/node_modules/.bin/vitest"

run_baseline() {
    PATH="$fake_bin:$PATH" bash "$sandbox/scripts/test_baseline.sh" "$@"
}

FAKE_RUST_COUNT="$rust_count" run_baseline >/dev/null
if frontend_mismatch_output="$(FAKE_FRONTEND_COUNT=$((frontend_count + 1)) \
    run_baseline --frontend 2>&1)"; then
    printf 'FAIL: frontend count mismatch was accepted\n' >&2
    exit 1
fi
if [[ "$frontend_mismatch_output" != *"baseline says $frontend_count"* ]]; then
    printf 'FAIL: frontend mismatch diagnostic was incomplete\n%s\n' \
        "$frontend_mismatch_output" >&2
    exit 1
fi
before_failed_frontend="$fixture/baseline-before-failed-frontend.json"
cp "$sandbox/tests/evidence/workspace-tests.json" "$before_failed_frontend"
if FAKE_FRONTEND_COUNT="$frontend_count" FAKE_FRONTEND_STATUS=7 \
    run_baseline --frontend >/dev/null 2>&1; then
    printf 'FAIL: failed frontend suite was accepted\n' >&2
    exit 1
fi
cmp "$before_failed_frontend" "$sandbox/tests/evidence/workspace-tests.json"

FAKE_FRONTEND_COUNT="$frontend_count" run_baseline --frontend >/dev/null

if mismatch_output="$(FAKE_RUST_COUNT=$((rust_count + 1)) run_baseline 2>&1)"; then
    printf 'FAIL: Rust count mismatch was accepted\n' >&2
    exit 1
fi
if [[ "$mismatch_output" != *"baseline says $rust_count"* ]]; then
    printf 'FAIL: Rust mismatch diagnostic was incomplete\n%s\n' "$mismatch_output" >&2
    exit 1
fi

before_failed_run="$fixture/baseline-before-failed-run.json"
cp "$sandbox/tests/evidence/workspace-tests.json" "$before_failed_run"
if FAKE_RUST_COUNT="$rust_count" FAKE_RUST_STATUS=7 run_baseline >/dev/null 2>&1; then
    printf 'FAIL: failed Rust suite was accepted\n' >&2
    exit 1
fi
cmp "$before_failed_run" "$sandbox/tests/evidence/workspace-tests.json"

legacy_read="$fixture/legacy-read.json"
python3 - "$sandbox/tests/evidence/workspace-tests.json" "$legacy_read" <<'PY'
import json
import sys

document = json.loads(open(sys.argv[1], encoding="utf-8").read())
document["version"] = 1
document["commit"] = {"tests": "c" * 40}
document["measured_at"] = {"tests": "2026-09-07T00:00:00Z"}
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(document))
PY
legacy_read_before="$fixture/legacy-read-before.json"
cp "$legacy_read" "$legacy_read_before"
if python3 "$recorder" --artifact "$legacy_read" --field tests --read >/dev/null 2>&1; then
    printf 'FAIL: --read accepted a legacy provenance artifact\n' >&2
    exit 1
fi
cmp "$legacy_read_before" "$legacy_read"

UPDATE_TEST_BASELINE=1 FAKE_RUST_COUNT=$((rust_count + 1)) run_baseline >/dev/null
python3 - "$sandbox/tests/evidence/workspace-tests.json" "$frontend_count" "$rust_count" <<'PY'
import json
import sys

document = json.loads(open(sys.argv[1], encoding="utf-8").read())
if document["tests"] != int(sys.argv[3]) + 1:
    raise SystemExit("wrapper did not record the selected Rust count")
if document["frontend_tests"] != int(sys.argv[2]):
    raise SystemExit("Rust wrapper update changed the frontend count")
PY

FAKE_FRONTEND_COUNT="$frontend_count" run_baseline --frontend >/dev/null
UPDATE_TEST_BASELINE=1 FAKE_FRONTEND_COUNT=$((frontend_count + 1)) \
    run_baseline --frontend >/dev/null
python3 - "$sandbox/tests/evidence/workspace-tests.json" "$frontend_count" "$rust_count" <<'PY'
import json
import sys

document = json.loads(open(sys.argv[1], encoding="utf-8").read())
if document["frontend_tests"] != int(sys.argv[2]) + 1:
    raise SystemExit("wrapper did not record the selected frontend count")
if document["tests"] != int(sys.argv[3]) + 1:
    raise SystemExit("frontend wrapper update changed the Rust count")
if "commit" in document or "measured_at" in document:
    raise SystemExit("wrapper reintroduced removed provenance metadata")
PY

# Updating one suite must preserve the other suite's independently measured
# count, without adding metadata for either one.
record "$artifact" tests "$((rust_count + 1))"
python3 - "$artifact" "$frontend_count" "$rust_count" <<'PY'
import json
import sys

document = json.loads(open(sys.argv[1], encoding="utf-8").read())
if document["tests"] != int(sys.argv[3]) + 1:
    raise SystemExit("Rust update did not land")
if document["frontend_tests"] != int(sys.argv[2]):
    raise SystemExit("Rust update rewrote the frontend count")
if "commit" in document or "measured_at" in document:
    raise SystemExit("Rust update reintroduced removed provenance metadata")
PY

record "$artifact" frontend_tests "$((frontend_count + 1))"
python3 - "$artifact" "$frontend_count" "$rust_count" <<'PY'
import json
import sys

document = json.loads(open(sys.argv[1], encoding="utf-8").read())
if document["frontend_tests"] != int(sys.argv[2]) + 1:
    raise SystemExit("frontend update did not land")
if document["tests"] != int(sys.argv[3]) + 1:
    raise SystemExit("frontend update rewrote the Rust count")
if "commit" in document or "measured_at" in document:
    raise SystemExit("frontend update reintroduced removed provenance metadata")
PY

# A v1 artifact already exists in released main. A real refresh migrates its
# useful counts and drops the fields whose meaning cannot be defended.
legacy_artifact="$fixture/legacy.json"
python3 - "$artifact" "$legacy_artifact" <<'PY'
import json
import sys

document = json.loads(open(sys.argv[1], encoding="utf-8").read())
document["version"] = 1
document["commit"] = {"tests": "b" * 40}
document["measured_at"] = {"tests": "2026-09-07T00:00:00Z"}
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(document))
PY
record "$legacy_artifact" tests "$rust_count"
python3 - "$legacy_artifact" "$rust_count" "$((frontend_count + 1))" <<'PY'
import json
import sys

document = json.loads(open(sys.argv[1], encoding="utf-8").read())
if document["version"] != 2 or document["tests"] != int(sys.argv[2]):
    raise SystemExit("legacy artifact was not migrated to schema 2")
if document["frontend_tests"] != int(sys.argv[3]):
    raise SystemExit("legacy migration changed the other suite count")
if "commit" in document or "measured_at" in document:
    raise SystemExit("legacy provenance metadata survived migration")
PY

# A dirty working tree is represented by the measured count only. The recorder
# must not turn HEAD into provenance for an uncommitted measurement.
dirty_repo="$fixture/dirty-repo"
mkdir -p "$dirty_repo"
git -C "$dirty_repo" init -q
git -C "$dirty_repo" config user.name baseline-test
git -C "$dirty_repo" config user.email baseline-test@example.invalid
printf 'one test\n' > "$dirty_repo/suite.txt"
git -C "$dirty_repo" add suite.txt
git -C "$dirty_repo" -c user.name=baseline-test -c user.email=baseline-test@example.invalid \
    commit -qm baseline
printf 'second test\n' >> "$dirty_repo/suite.txt"
if git -C "$dirty_repo" diff --quiet; then
    printf 'FAIL: dirty-worktree fixture did not become dirty\n' >&2
    exit 1
fi
dirty_artifact="$dirty_repo/workspace-tests.json"
record "$dirty_artifact" tests 2
python3 - "$dirty_artifact" <<'PY'
import json
import sys

document = json.loads(open(sys.argv[1], encoding="utf-8").read())
if document["tests"] != 2:
    raise SystemExit("dirty-worktree measurement was not recorded")
if "commit" in document or "measured_at" in document:
    raise SystemExit("dirty-worktree measurement acquired false HEAD provenance")
PY

# A squash-equivalent tree is valid even though the contributor commit is not an
# ancestor of the squash commit. The count-only contract has no ancestry rule to
# reject it.
squash_repo="$fixture/squash-repo"
mkdir -p "$squash_repo"
git -C "$squash_repo" init -q
git -C "$squash_repo" config user.name baseline-test
git -C "$squash_repo" config user.email baseline-test@example.invalid
printf 'base\n' > "$squash_repo/suite.txt"
git -C "$squash_repo" add suite.txt
git -C "$squash_repo" -c user.name=baseline-test -c user.email=baseline-test@example.invalid \
    commit -qm base
git -C "$squash_repo" branch -M main
git -C "$squash_repo" branch contributor
git -C "$squash_repo" switch -q contributor
printf 'base\nnew test\n' > "$squash_repo/suite.txt"
git -C "$squash_repo" add suite.txt
git -C "$squash_repo" -c user.name=baseline-test -c user.email=baseline-test@example.invalid \
    commit -qm contributor
contributor_commit="$(git -C "$squash_repo" rev-parse HEAD)"
git -C "$squash_repo" switch -q main
git -C "$squash_repo" switch -q -c squash
printf 'base\nnew test\n' > "$squash_repo/suite.txt"
git -C "$squash_repo" add suite.txt
git -C "$squash_repo" -c user.name=baseline-test -c user.email=baseline-test@example.invalid \
    commit -qm squash
squash_commit="$(git -C "$squash_repo" rev-parse HEAD)"
if git -C "$squash_repo" merge-base --is-ancestor "$contributor_commit" "$squash_commit"; then
    printf 'FAIL: squash fixture unexpectedly preserved contributor ancestry\n' >&2
    exit 1
fi
squash_a="$fixture/squash-a.json"
squash_b="$fixture/squash-b.json"
(cd "$squash_repo" && record "$squash_a" tests 2)
(cd "$squash_repo" && git switch -q contributor && record "$squash_b" tests 2)
cmp "$squash_a" "$squash_b"

printf 'Test-baseline provenance contract passed.\n'
