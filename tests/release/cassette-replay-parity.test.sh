#!/usr/bin/env bash
# The proof #182 asks for, as a comparison of two committed artifacts.
#
# The replay gate exists so the story suite can run in CI with no network and no
# spend. That is only worth anything if a replay of a cassette reproduces the run
# that recorded it — otherwise a green replay proves the cassette is intact, not
# that the suite passes.
#
# So this compares the record run against the replay run and asserts, per #182's
# acceptance criteria:
#
#   * zero misses for every story that produced a successful live response.
#     A story that FAILED live is excluded on purpose and only there: its call
#     errored during recording, so nothing was ever stored for it, and a miss on
#     replay is the correct and expected consequence. That is not the same as
#     excluding a story from the suite — it still runs, and it still fails.
#   * every story that passed live also passes on replay. A replay that serves a
#     recorded answer but reaches a different verdict means the recording does
#     not describe the run.
#   * no story was dropped from the family to make the numbers work: both runs
#     cover the same story set, of the same size.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECORD="$ROOT/tests/evidence/story-runs/ubuntu-22.04-gpt-oss-120b.json"
REPLAY="$ROOT/tests/evidence/story-runs/ubuntu-22.04-gpt-oss-120b.replay.json"
CASSETTE="$ROOT/tests/e2e/cassettes/ubuntu-jammy-gpt-oss-120b.json"

for f in "$RECORD" "$REPLAY" "$CASSETTE"; do
    [ -f "$f" ] || { echo "FAIL: missing $f"; exit 1; }
done

python3 - "$RECORD" "$REPLAY" "$CASSETTE" <<'PY'
import hashlib
import json
import sys

record = json.load(open(sys.argv[1]))
replay = json.load(open(sys.argv[2]))
cassette_bytes = open(sys.argv[3], "rb").read()

failures = []

# The two runs must describe the same thing, or the comparison is meaningless.
for field in ("story_set", "release", "distro_id", "surface"):
    if record.get(field) != replay.get(field):
        failures.append(
            f"{field} differs: record={record.get(field)!r} replay={replay.get(field)!r}"
        )
if record["cassette_mode"] != "record":
    failures.append(f"the record artifact is mode {record['cassette_mode']!r}")
if replay["cassette_mode"] != "replay":
    failures.append(f"the replay artifact is mode {replay['cassette_mode']!r}")

# Both runs cover the same stories: nothing dropped to make the gate pass.
rec_ids, rep_ids = set(record["stories"]), set(replay["stories"])
if rec_ids != rep_ids:
    only_rec, only_rep = sorted(rec_ids - rep_ids), sorted(rep_ids - rec_ids)
    failures.append(f"story sets differ — record-only {only_rec}, replay-only {only_rep}")
if record["totals"]["total"] != replay["totals"]["total"]:
    failures.append(
        f"story counts differ: {record['totals']['total']} vs {replay['totals']['total']}"
    )

# The replay must have run against the cassette that is committed beside it.
actual_sha = hashlib.sha256(cassette_bytes).hexdigest()
if replay.get("cassette_sha256") != actual_sha:
    failures.append(
        "the replay ran against a different cassette than the one committed "
        f"(artifact {str(replay.get('cassette_sha256'))[:16]}…, file {actual_sha[:16]}…)"
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
        f"stories that passed live but not on replay: {regressed} — the recording "
        "does not describe the run it came from"
    )

audit = replay.get("cassette_audit", {})
misses = audit.get("misses", 0)
if misses > len(failed_live):
    failures.append(
        f"{misses} miss(es) but only {len(failed_live)} story/stories failed live "
        f"({failed_live}); at least one story with a recorded answer still missed"
    )
if audit.get("served", 0) <= 0:
    failures.append("the replay served no calls — it did not exercise the cassette")

if failures:
    for f in failures:
        print("FAIL:", f)
    sys.exit(1)

print(f"ok: {len(passed_live)}/{len(rec_ids)} stories passed live and all of them replay")
print(f"ok: {audit.get('served')} call(s) served, {misses} miss(es), "
      f"accounted for by {len(failed_live)} story/stories that errored live {failed_live}")
print("ok: both runs cover the same story set, against the committed cassette")
PY
