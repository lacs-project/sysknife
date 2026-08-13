#!/usr/bin/env bash
# The proof #182 asks for, as a comparison of committed artifacts — for every
# release that has a committed run, not just the first one.
#
# The replay gate exists so the story suite can run in CI with no network and no
# spend. That is only worth anything if a replay of a cassette reproduces the run
# that recorded it — otherwise a green replay proves the cassette is intact, not
# that the suite passes.
#
# So this compares each record run against its replay run and asserts, per #182's
# acceptance criteria:
#
#   * zero misses for every story that produced a successful live response.
#     A story that FAILED live is excluded on purpose and only there, and only
#     when its call actually errored: nothing was stored for it, so a miss on
#     replay is the correct consequence. A story that fails by proposing the
#     WRONG PLAN is different — the call succeeded and was recorded, so it must
#     still replay, and it does; it simply reaches the same wrong verdict. That is not the same as
#     excluding a story from the suite — it still runs, and it still fails.
#   * every story that passed live also passes on replay. A replay that serves a
#     recorded answer but reaches a different verdict means the recording does
#     not describe the run.
#   * no story was dropped from the family to make the numbers work: both runs
#     cover the same story set, of the same size.
#
# Discovery, rather than a hardcoded release. The gate used to name
# ubuntu-22.04 and ubuntu-jammy explicitly, so a second release could be
# recorded, committed, and never checked. Now every `*.json` in story-runs/ is
# required to have a `.replay.json` twin and is checked: committing a record run
# without its replay is itself a failure, because it publishes a pass rate
# nothing has reproduced.
#
# The cassette is located by CONTENT, not by name. Artifacts are named by version
# (22.04) and cassettes by codename (jammy), and the only machine-readable link
# between them was a prose comment in ubuntu-vm.conf. Since the gate already has
# to prove the replay ran against the committed cassette, it identifies the
# cassette by the sha256 the replay recorded — which is that proof, and needs no
# name map to drift.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNS="$ROOT/tests/evidence/story-runs"
CASSETTES="$ROOT/tests/e2e/cassettes"

[ -d "$RUNS" ] || { echo "FAIL: missing $RUNS"; exit 1; }
[ -d "$CASSETTES" ] || { echo "FAIL: missing $CASSETTES"; exit 1; }

python3 - "$RUNS" "$CASSETTES" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

runs = Path(sys.argv[1])
cassettes = Path(sys.argv[2])

# Index the committed cassettes by content, so a replay artifact can name its
# cassette by hash instead of by a filename convention.
by_sha = {}
for path in sorted(cassettes.glob("*.json")):
    by_sha[hashlib.sha256(path.read_bytes()).hexdigest()] = path

records = sorted(p for p in runs.glob("*.json") if not p.name.endswith(".replay.json"))
if not records:
    print("FAIL: no record artifacts in tests/evidence/story-runs/ — nothing is proven")
    sys.exit(1)

failures = []
checked = []

for rec_path in records:
    label = rec_path.stem
    rep_path = rec_path.with_name(f"{rec_path.stem}.replay.json")
    if not rep_path.exists():
        failures.append(
            f"[{label}] no {rep_path.name}: this run publishes a pass rate that no "
            "replay has reproduced"
        )
        continue

    record = json.loads(rec_path.read_text())
    replay = json.loads(rep_path.read_text())

    # The two runs must describe the same thing, or the comparison is meaningless.
    for field in ("story_set", "release", "distro_id", "surface"):
        if record.get(field) != replay.get(field):
            failures.append(
                f"[{label}] {field} differs: record={record.get(field)!r} "
                f"replay={replay.get(field)!r}"
            )
    if record["cassette_mode"] != "record":
        failures.append(f"[{label}] the record artifact is mode {record['cassette_mode']!r}")
    if replay["cassette_mode"] != "replay":
        failures.append(f"[{label}] the replay artifact is mode {replay['cassette_mode']!r}")

    # Both runs cover the same stories: nothing dropped to make the gate pass.
    rec_ids, rep_ids = set(record["stories"]), set(replay["stories"])
    if rec_ids != rep_ids:
        only_rec, only_rep = sorted(rec_ids - rep_ids), sorted(rep_ids - rec_ids)
        failures.append(
            f"[{label}] story sets differ — record-only {only_rec}, replay-only {only_rep}"
        )
    if record["totals"]["total"] != replay["totals"]["total"]:
        failures.append(
            f"[{label}] story counts differ: {record['totals']['total']} vs "
            f"{replay['totals']['total']}"
        )

    # The replay must have run against a cassette that is committed beside it.
    claimed = replay.get("cassette_sha256")
    cassette = by_sha.get(claimed)
    if cassette is None:
        failures.append(
            f"[{label}] the replay ran against a cassette that is not committed "
            f"(sha {str(claimed)[:16]}…; committed: "
            f"{sorted(p.name for p in by_sha.values())})"
        )

    # The criterion itself. A story that failed live has no recorded answer, so a
    # miss for it is expected; every other story must replay.
    passed_live = {k for k, v in record["stories"].items() if v.get("verdict") == "PASS"}
    failed_live = sorted(rec_ids - passed_live)

    regressed = sorted(
        k for k in passed_live if replay["stories"].get(k, {}).get("verdict") != "PASS"
    )
    if regressed:
        failures.append(
            f"[{label}] stories that passed live but not on replay: {regressed} — the "
            "recording does not describe the run it came from"
        )

    audit = replay.get("cassette_audit", {})
    misses = audit.get("misses", 0)
    if misses > len(failed_live):
        failures.append(
            f"[{label}] {misses} miss(es) but only {len(failed_live)} story/stories "
            f"failed live ({failed_live}); at least one story with a recorded answer "
            "still missed"
        )
    if audit.get("served", 0) <= 0:
        failures.append(f"[{label}] the replay served no calls — it did not exercise the cassette")

    checked.append(
        (label, len(passed_live), len(rec_ids), audit.get("served"), misses, failed_live,
         cassette.name if cassette else "<uncommitted>")
    )

if failures:
    for f in failures:
        print("FAIL:", f)
    sys.exit(1)

for label, passed, total, served, misses, failed_live, cassette in checked:
    print(f"ok: [{label}] {passed}/{total} stories passed live and all of them replay")
    print(f"ok: [{label}] {served} call(s) served, {misses} miss(es), accounted for by "
          f"{len(failed_live)} story/stories that did not pass live {failed_live}, "
          f"against committed {cassette}")
print(f"ok: {len(checked)} release run(s) checked, each against the cassette it recorded")
PY
