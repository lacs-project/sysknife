#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="${repo_root}/scripts/check_public_claims.sh"

if [[ ! -x "$checker" ]]; then
    printf 'FAIL: public-claims checker is missing or not executable: %s\n' "$checker" >&2
    exit 1
fi

"$checker" "$repo_root"

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

# Copy the COMPLETE set of files the checker inspects. If any input is missing
# the checker aborts on its existence check before evaluating claims, which
# would make every assert_rejected below pass vacuously.
#
# The claim files are read out of check_evidence_claims.py rather than retyped.
# They used to be a second hand-maintained copy of CLAIM_FILES, and the moment
# that list grew, this one did not: the checker aborted on a file the fixture had
# never heard of, and the whole contract test failed for a reason unrelated to
# any claim. A guard whose fixture has to be edited in lockstep with the thing it
# guards will eventually guard nothing.
mapfile -t claim_files_from_checker < <(
    python3 - "$repo_root/scripts/check_evidence_claims.py" <<'PYEOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("checker", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print("\n".join(mod.CLAIM_FILES))
PYEOF
)

fixture_files=(
    "${claim_files_from_checker[@]}"
    "assets/demo/mcp-flow-mock.sh"
    # Evidence the numeric claims derive from, and the source the action count is
    # counted out of. Without these the checker aborts on its own input check and
    # every assert_rejected below would pass for the wrong reason.
    "tests/evidence/workspace-tests.json"
    "crates/sysknife-brain/src/planning_tools/propose_plan.rs"
)

# The committed story runs that back the published pass rates and decide which
# releases may be tiered "Validated". Copied as a set rather than named one by
# one: naming them meant the fixture held 22.04's record run and not its replay,
# so the tier rule — which requires a record AND a replay — saw no verified
# release at all, and a doc stating the accurate tier would have failed the
# pristine check for a reason that had nothing to do with the doc.
mkdir -p "$fixture/tests/evidence/story-runs"
cp "$repo_root"/tests/evidence/story-runs/*.json "$fixture/tests/evidence/story-runs/"
for rel in "${fixture_files[@]}"; do
    mkdir -p "$fixture/$(dirname "$rel")"
    cp "$repo_root/$rel" "$fixture/$rel"
done

# The story files themselves: a bare "N-story suite" claim is checked against the
# suite and family sizes counted from these headers, so without them a legitimate
# figure (the 54-story atomic family, which no recorded run covers) reads as
# fabricated and the pristine fixture fails.
#
# The canonical parser travels with them. The checker derives families by
# running tests/e2e/run-stories.sh --metadata out of the tree under check, not
# by parsing headers itself, so the fixture carries that runner too — without
# it the derivation fails closed and the pristine check below fails.
mkdir -p "$fixture/tests/e2e/stories"
cp "$repo_root"/tests/e2e/stories/story-*.sh "$fixture/tests/e2e/stories/"
cp "$repo_root/tests/e2e/run-stories.sh" "$fixture/tests/e2e/run-stories.sh"

# Guard against re-introducing the vacuous-fixture bug: the pristine copy must
# PASS, proving rejections below come from the mutation, not a missing input.
if ! "$checker" "$fixture" >/dev/null 2>&1; then
    printf 'FAIL: pristine fixture rejected — fixture is incomplete\n' >&2
    exit 1
fi

assert_rejected_with_diagnostic() {
    local label="$1"
    shift
    local output expected
    if output=$("$checker" "$fixture" 2>&1); then
        printf 'FAIL: checker accepted stale claim: %s\n' "$label" >&2
        exit 1
    fi
    for expected in "$@"; do
        if [[ "$output" != *"$expected"* ]]; then
            printf 'FAIL: diagnostic for %s omitted %s\n%s\n' \
                "$label" "$expected" "$output" >&2
            exit 1
        fi
    done
}

# The story coverage sentence is a derived claim, not a second catalogue. Mutate
# its published All-family figure without repeating today's value in this test.
read -r derived_all published_all < <(
    python3 - "$fixture/CONTRIBUTING.md" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
pattern = re.compile(
    r"(of the action names available on both families,\s*)(\d+)"
    r"(\s+are still untouched by any story)"
)
match = pattern.search(text)
if not match:
    raise SystemExit("could not find the story coverage figure in the fixture")
old = int(match.group(2))
new = old + 1
path.write_text(
    text[:match.start(2)] + str(new) + text[match.end(2):], encoding="utf-8"
)
print(old, new)
PY
)
if [[ -z "${derived_all:-}" || -z "${published_all:-}" ]]; then
    printf 'FAIL: story-coverage mutation produced no values\n' >&2
    exit 1
fi
if ! grep -Fq "$published_all are still untouched by any story" \
    "$fixture/CONTRIBUTING.md"; then
    printf 'FAIL: story-coverage mutation did not apply\n' >&2
    exit 1
fi
assert_rejected_with_diagnostic \
    'published story-coverage figure that disagrees with the tree' \
    "published $published_all" "derived $derived_all"
cp "$repo_root/CONTRIBUTING.md" "$fixture/CONTRIBUTING.md"

# Change only the story evidence. Pick an actually uncovered catalogue row from
# the fixture rather than keeping a second action list in this test.
read -r covered_action covered_family covered_before covered_after < <(
    python3 - "$fixture/docs/action-reference.md" "$fixture/tests/e2e/stories" <<'PY'
import re
import sys
from collections import Counter
from pathlib import Path

catalogue = Path(sys.argv[1]).read_text(encoding="utf-8")
story_dir = Path(sys.argv[2])
rows = re.findall(
    r"^\| `([A-Za-z0-9_]+)` \|.*?\| (All|Ubuntu|Fedora) \|",
    catalogue,
    re.MULTILINE,
)
if not rows:
    raise SystemExit("could not derive catalogue rows for the story mutation")
story_files = sorted(story_dir.glob("story-*.sh"))
if not story_files:
    raise SystemExit("could not derive story files for the story mutation")
named = set()
for story in story_files:
    named.update(
        re.findall(
            r'"([A-Za-z0-9_]+)"',
            story.read_text(encoding="utf-8", errors="replace"),
        )
    )
counts = Counter(family for name, family in rows if name not in named)
candidates = sorted((name, family) for name, family in rows if name not in named)
if not candidates:
    raise SystemExit("fixture has no uncovered action to mutate")
action, family = candidates[0]
target = story_files[0]
target.write_text(
    target.read_text(encoding="utf-8") + f'\n# coverage fixture: "{action}"\n',
    encoding="utf-8",
)
before = counts[family]
print(action, family, before, before - 1)
PY
)
if [[ -z "${covered_action:-}" || -z "${covered_family:-}" ]]; then
    printf 'FAIL: story-evidence mutation produced no candidate\n' >&2
    exit 1
fi
if ! grep -R -Fq "\"$covered_action\"" "$fixture/tests/e2e/stories"; then
    printf 'FAIL: story-evidence mutation did not apply for %s\n' "$covered_action" >&2
    exit 1
fi
assert_rejected_with_diagnostic \
    'story evidence that makes the published coverage stale' \
    "published $covered_before" "derived $covered_after"
cp "$repo_root"/tests/e2e/stories/story-*.sh "$fixture/tests/e2e/stories/"
if ! "$checker" "$fixture" >/dev/null 2>&1; then
    printf 'FAIL: restored story fixture rejected — mutation result is meaningless\n' >&2
    exit 1
fi

# A moved public anchor must fail with its intended explanation, not merely with
# a non-zero status from an empty grep assignment under pipefail.
python3 - "$fixture/CONTRIBUTING.md" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = "of the action names available on both families"
new = "of the action names available across both families"
if text.count(old) != 1:
    raise SystemExit("story coverage anchor was not unique in the fixture")
path.write_text(text.replace(old, new), encoding="utf-8")
PY
if ! grep -Fq 'available across both families' "$fixture/CONTRIBUTING.md"; then
    printf 'FAIL: story-coverage anchor mutation did not apply\n' >&2
    exit 1
fi
assert_rejected_with_diagnostic \
    'story-coverage claim whose anchor moved' \
    'could not derive story coverage claim' 'CONTRIBUTING.md'
cp "$repo_root/CONTRIBUTING.md" "$fixture/CONTRIBUTING.md"
if ! "$checker" "$fixture" >/dev/null 2>&1; then
    printf 'FAIL: restored public-claims fixture rejected — pristine assertion is invalid\n' >&2
    exit 1
fi

# Generic family labels must match the family they name. Publishing the Ubuntu
# count as the atomic count uses two individually legitimate sizes, so a rule
# that only checks set membership passes it with the families swapped. This
# mutates a file the CONTRIBUTING sentence check never reads, proving the
# generic rule itself bites. Both counts are derived from the fixture.
read -r derived_atomic derived_ubuntu < <(
    python3 - "$repo_root/scripts/check_evidence_claims.py" "$fixture" <<'PY'
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("checker", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
sizes = mod.story_family_sizes(Path(sys.argv[2]))
if not sizes:
    raise SystemExit("could not derive story families for the label mutation")
print(sizes["atomic"], sizes["ubuntu"])
PY
)
if [[ -z "${derived_atomic:-}" || -z "${derived_ubuntu:-}" ]]; then
    printf 'FAIL: family-label mutation produced no values\n' >&2
    exit 1
fi
wrong_atomic="$derived_ubuntu"
if [[ "$wrong_atomic" == "$derived_atomic" ]]; then
    wrong_atomic=$((derived_atomic + 1))
fi
printf '\nThe atomic family holds %s atomic stories.\n' "$wrong_atomic" \
    >> "$fixture/docs/introduction.md"
if ! grep -Fq "$wrong_atomic atomic stories" "$fixture/docs/introduction.md"; then
    printf 'FAIL: family-label mutation did not apply\n' >&2
    exit 1
fi
assert_rejected_with_diagnostic \
    'family label naming the wrong derived size' \
    "$wrong_atomic" "atomic" "derived $derived_atomic"
cp "$repo_root/docs/introduction.md" "$fixture/docs/introduction.md"

# The stale-gap direction with the gap closed: the tree leaves zero Ubuntu-only
# actions uncovered, so a nonzero gap sentence written into the prose must be
# rejected against derived zero. Nothing here retypes today's counts; the
# premise (derived zero) and the published figure are both read out.
read -r gap_published gap_derived < <(
    python3 - "$fixture" "$repo_root/scripts/check_evidence_claims.py" <<'PY'
import importlib.util
import re
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("checker", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fixture = Path(sys.argv[1])
derived = mod.uncovered_action_counts(fixture)["Ubuntu"]
if derived != 0:
    raise SystemExit(
        f"fixture gap is not zero before the stale-prose mutation: {derived}"
    )
path = fixture / "CONTRIBUTING.md"
text = path.read_text(encoding="utf-8")
old = "and every Debian-only action has a story."
new = "and one Debian-only action still has no story: `GrubSetKargs`."
if text.count(old) != 1:
    raise SystemExit("universal Debian-only sentence was not unique in the fixture")
path.write_text(text.replace(old, new), encoding="utf-8")
found = re.search(
    mod.DEBIAN_GAP_PROSE,
    re.sub(r"\s+", " ", path.read_text(encoding="utf-8")),
    re.IGNORECASE,
)
if not found:
    raise SystemExit("stale-prose mutation did not apply")
print(mod._claim_count(found.group("count")), derived)
PY
)
if [[ -z "${gap_published:-}" || -z "${gap_derived:-}" ]]; then
    printf 'FAIL: gap-closure mutation produced no values\n' >&2
    exit 1
fi
if [[ "$gap_derived" != "0" ]]; then
    printf 'FAIL: gap-closure mutation did not close the derived gap (derived %s)\n' \
        "$gap_derived" >&2
    exit 1
fi
if ! grep -Fq 'one Debian-only action still has no story' \
    "$fixture/CONTRIBUTING.md"; then
    printf 'FAIL: stale-prose mutation did not apply\n' >&2
    exit 1
fi
assert_rejected_with_diagnostic \
    'stale nonzero gap prose against a derived zero gap' \
    "published $gap_published" "derived $gap_derived"
cp "$repo_root/CONTRIBUTING.md" "$fixture/CONTRIBUTING.md"
if ! "$checker" "$fixture" >/dev/null 2>&1; then
    printf 'FAIL: restored gap fixture rejected — mutation result is meaningless\n' >&2
    exit 1
fi

# The universal "every Debian-only action" claim is screened in every claim
# file, not just CONTRIBUTING. The tree now covers the whole gap, so reopen
# one in the fixture evidence — by neutralising the quoted action name in the
# fixture story that carries the coverage — and prove the global rule rejects
# the pristine universal prose against the derived count. The premise (derived
# zero before, derived one after) is read out of the fixture, not retyped, and
# the diagnostic must name introduction.md: the CONTRIBUTING mismatch the same
# evidence also produces is not sufficient proof for this rule.
read -r debian_before debian_uncovered < <(
    python3 - "$fixture" \
        "$repo_root/scripts/check_evidence_claims.py" <<'PY'
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("checker", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fixture = Path(sys.argv[1])
before = mod.uncovered_action_counts(fixture)["Ubuntu"]
if before != 0:
    raise SystemExit(
        f"fixture gap is not zero before the uncover mutation: {before}"
    )
story_dir = fixture / "tests/e2e/stories"
holders = sorted(
    path for path in story_dir.glob("story-*.sh")
    if '"GrubSetKargs"' in path.read_text(encoding="utf-8", errors="replace")
)
if len(holders) != 1:
    raise SystemExit(
        "expected exactly one fixture story to quote GrubSetKargs, "
        f"found {len(holders)}"
    )
target = holders[0]
text = target.read_text(encoding="utf-8")
if text.count('"GrubSetKargs"') != 1:
    raise SystemExit("GrubSetKargs quote was not unique in the fixture story")
target.write_text(
    text.replace('"GrubSetKargs"', '"GrubSetKargsFixture"'), encoding="utf-8"
)
after = mod.uncovered_action_counts(fixture)["Ubuntu"]
if after != 1:
    raise SystemExit(
        f"uncover mutation did not reopen a gap of one (derived {after})"
    )
print(before, after)
PY
)
if [[ -z "${debian_before:-}" || -z "${debian_uncovered:-}" ]]; then
    printf 'FAIL: universal-claim mutation produced no derived count\n' >&2
    exit 1
fi
if ! grep -R -Fq '"GrubSetKargsFixture"' \
    "$fixture/tests/e2e/stories"; then
    printf 'FAIL: uncover mutation did not apply\n' >&2
    exit 1
fi
assert_rejected_with_diagnostic \
    'universal Debian-only claim against a reopened gap' \
    'introduction.md' "leaves $debian_uncovered Ubuntu-only"
cp "$repo_root"/tests/e2e/stories/story-*.sh "$fixture/tests/e2e/stories/"
if ! "$checker" "$fixture" >/dev/null 2>&1; then
    printf 'FAIL: restored uncover fixture rejected — mutation result is meaningless\n' >&2
    exit 1
fi

# The introduction's Debian-only prose is derived, not trusted: with the tree
# untouched (derived gap zero), restate its universal sentence as a stale
# nonzero gap and prove rejection names the file and both figures.
read -r intro_published intro_derived < <(
    python3 - "$fixture" \
        "$repo_root/scripts/check_evidence_claims.py" <<'PY'
import importlib.util
import re
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("checker", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fixture = Path(sys.argv[1])
derived = mod.uncovered_action_counts(fixture)["Ubuntu"]
if derived != 0:
    raise SystemExit(
        f"fixture gap is not zero before the introduction mutation: {derived}"
    )
path = fixture / "docs/introduction.md"
text = path.read_text(encoding="utf-8")
old = "Every Debian-only action has a story."
new = "One Debian-only action still has no story."
if text.count(old) != 1:
    raise SystemExit("universal Debian-only sentence was not unique in the fixture")
path.write_text(text.replace(old, new), encoding="utf-8")
found = re.search(
    mod.DEBIAN_GAP_PROSE,
    re.sub(r"\s+", " ", path.read_text(encoding="utf-8")),
    re.IGNORECASE,
)
if not found:
    raise SystemExit("introduction-count mutation did not apply")
print(mod._claim_count(found.group("count")), derived)
PY
)
if [[ -z "${intro_published:-}" || -z "${intro_derived:-}" ]]; then
    printf 'FAIL: introduction-count mutation produced no values\n' >&2
    exit 1
fi
if ! grep -Fq 'One Debian-only action still has no story' \
    "$fixture/docs/introduction.md"; then
    printf 'FAIL: introduction-count mutation did not apply\n' >&2
    exit 1
fi
assert_rejected_with_diagnostic \
    'introduction gap count that disagrees with the tree' \
    'introduction.md' "published $intro_published" "derived $intro_derived"
cp "$repo_root/docs/introduction.md" "$fixture/docs/introduction.md"

# ...and the other direction for the same sentence: reopen a gap of one in the
# fixture evidence while the introduction prose states a different nonzero
# count. The candidate gap and both figures are derived from the fixture, and
# the diagnostic must name this file — the CONTRIBUTING mismatch the same
# evidence also produces is not sufficient proof for this rule.
read -r intro_before intro_after < <(
    python3 - "$fixture" \
        "$repo_root/scripts/check_evidence_claims.py" <<'PY'
import importlib.util
import re
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("checker", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fixture = Path(sys.argv[1])
before = mod.uncovered_action_counts(fixture)["Ubuntu"]
if before != 0:
    raise SystemExit(
        f"fixture gap is not zero before the intro-evidence mutation: {before}"
    )
story_dir = fixture / "tests/e2e/stories"
holders = sorted(
    path for path in story_dir.glob("story-*.sh")
    if '"GrubSetKargs"' in path.read_text(encoding="utf-8", errors="replace")
)
if len(holders) != 1:
    raise SystemExit(
        "expected exactly one fixture story to quote GrubSetKargs, "
        f"found {len(holders)}"
    )
target = holders[0]
story_text = target.read_text(encoding="utf-8")
if story_text.count('"GrubSetKargs"') != 1:
    raise SystemExit("GrubSetKargs quote was not unique in the fixture story")
target.write_text(
    story_text.replace('"GrubSetKargs"', '"GrubSetKargsFixture"'),
    encoding="utf-8",
)
after = mod.uncovered_action_counts(fixture)["Ubuntu"]
if after != 1:
    raise SystemExit(
        f"intro-evidence mutation did not reopen a gap of one (derived {after})"
    )
intro_path = fixture / "docs/introduction.md"
intro_text = intro_path.read_text(encoding="utf-8")
old = "Every Debian-only action has a story."
new = "Two Debian-only actions still have no story."
if intro_text.count(old) != 1:
    raise SystemExit("universal Debian-only sentence was not unique in the fixture")
intro_path.write_text(intro_text.replace(old, new), encoding="utf-8")
found = re.search(
    mod.DEBIAN_GAP_PROSE,
    re.sub(r"\s+", " ", intro_path.read_text(encoding="utf-8")),
    re.IGNORECASE,
)
if not found or mod._claim_count(found.group("count")) != 2:
    raise SystemExit("introduction-evidence mutation did not apply")
print(mod._claim_count(found.group("count")), after)
PY
)
if [[ -z "${intro_before:-}" || -z "${intro_after:-}" ]]; then
    printf 'FAIL: introduction-evidence mutation produced no values\n' >&2
    exit 1
fi
if ! grep -Fq 'Two Debian-only actions still have no story' \
    "$fixture/docs/introduction.md"; then
    printf 'FAIL: introduction-evidence mutation did not apply\n' >&2
    exit 1
fi
assert_rejected_with_diagnostic \
    'story evidence that makes the introduction gap stale' \
    'introduction.md' "published $intro_before" "derived $intro_after"
cp "$repo_root"/tests/e2e/stories/story-*.sh "$fixture/tests/e2e/stories/"
cp "$repo_root/docs/introduction.md" "$fixture/docs/introduction.md"
if ! "$checker" "$fixture" >/dev/null 2>&1; then
    printf 'FAIL: restored intro-evidence fixture rejected — mutation result is meaningless\n' >&2
    exit 1
fi

# The harness parses the story header from line 2, and the checker delegates to
# the harness rather than parsing headers itself. A header shifted off line 2
# is rejected by the runner; the evidence derivation has to fail loudly through
# that same path rather than silently derive a different family table.
read -r moved_story < <(
    python3 - "$fixture/tests/e2e/stories" <<'PY'
import sys
from pathlib import Path

story_dir = Path(sys.argv[1])
target = sorted(story_dir.glob("story-*.sh"))[0]
lines = target.read_text(encoding="utf-8").splitlines()
if len(lines) < 2 or not lines[1].startswith("# Story"):
    raise SystemExit("fixture header is not on line 2 as expected")
target.write_text(
    "# fixture: shifted header\n" + target.read_text(encoding="utf-8"),
    encoding="utf-8",
)
print(target.name)
PY
)
if [[ -z "${moved_story:-}" ]]; then
    printf 'FAIL: header-location mutation produced no target\n' >&2
    exit 1
fi
if sed -n '2p' "$fixture/tests/e2e/stories/$moved_story" | grep -q '^# Story'; then
    printf 'FAIL: header-location mutation did not move the header off line 2\n' >&2
    exit 1
fi
assert_rejected_with_diagnostic \
    'story header moved from the production line-2 location' \
    'could not derive story families' "$moved_story"
cp "$repo_root"/tests/e2e/stories/story-*.sh "$fixture/tests/e2e/stories/"
if ! "$checker" "$fixture" >/dev/null 2>&1; then
    printf 'FAIL: restored header fixture rejected — mutation result is meaningless\n' >&2
    exit 1
fi

assert_rejected() {
    local label="$1"
    if "$checker" "$fixture" >/dev/null 2>&1; then
        printf 'FAIL: checker accepted stale claim: %s\n' "$label" >&2
        exit 1
    fi
}

# Derive the baseline from the evidence artifact rather than repeating the
# literal here. When the baseline moved, this mutation silently became a no-op:
# the sed matched nothing, the checker legitimately passed, and the assertion
# below then blamed the checker. A test whose mutation can stop mutating is worse
# than no test — so every mutation below is confirmed to have applied.
baseline="$(python3 -c "
import json,sys
print(f\"{json.load(open(sys.argv[1]))['tests']:,}\")
" "$repo_root/tests/evidence/workspace-tests.json")"
if [[ -z "$baseline" ]]; then
    printf 'FAIL: could not read the test count from the evidence artifact\n' >&2
    exit 1
fi
sed -i "s/${baseline} Rust tests/1,256 Rust tests/" "$fixture/README.md"
if ! grep -q '1,256 Rust tests' "$fixture/README.md"; then
    printf 'FAIL: baseline mutation did not apply; fixture would pass vacuously\n' >&2
    exit 1
fi
assert_rejected 'test count that disagrees with the evidence artifact'
cp "$repo_root/README.md" "$fixture/README.md"

# A figure with no artifact at all behind it. This is the "65/65 stories" shape:
# published for months, never produced by a run.
printf '\nUbuntu 24.04 is validated with 47/50 stories on a live VM.\n' >> "$fixture/README.md"
assert_rejected 'story pass rate with no recorded run'
cp "$repo_root/README.md" "$fixture/README.md"

# ...and the same claim IS accepted once a run records it. Without this the rule
# could simply reject every story claim and every mutation above would still pass.
mkdir -p "$fixture/tests/evidence/story-runs"
# Produced by the real writer, not hand-written. A hand-written fixture meant the
# writer and the checker were never round-tripped, and the writer was emitting
# invalid JSON for every run of two or more stories without anything noticing.
write_fixture_run() {
    local story_set="$1" total="$2" passed="$3" verdict="$4"
    local rows="" i
    for ((i = 1; i <= total; i++)); do
        rows+="$i"$'\t'"PASS"$'\t'"story number $i, \"quoted\" and back\\slashed"$'\n'
    done
    printf '%s' "$rows" \
        | EV_PATH="$fixture/tests/evidence/story-runs/fixture-run.json" \
          EV_DISTRO_ID=ubuntu EV_RELEASE=24.04 \
          EV_SURFACE="groq/openai/gpt-oss-120b" \
          EV_CASSETTE_MODE=replay EV_CASSETTE_SHA=deadbeef \
          EV_CASSETTE_HITS=61 EV_CASSETTE_MISSES=0 EV_CASSETTE_VERDICT="$verdict" \
          EV_STORY_SET="$story_set" EV_RAN_AT="1970-01-01T00:00:00+00:00" \
          EV_TOTAL="$total" EV_PASSED="$passed" EV_FAILED="$((total - passed))" \
          EV_SKIPPED=0 EV_RATELIMITED=0 \
          python3 "$repo_root/scripts/record_story_run.py"
}
write_fixture_run ubuntu 50 47 ok
# The writer's output must be valid JSON — the defect it replaced was not.
python3 -m json.tool "$fixture/tests/evidence/story-runs/fixture-run.json" >/dev/null \
    || { printf 'FAIL: record_story_run.py emitted invalid JSON\n' >&2; exit 1; }
printf '\nUbuntu 24.04 is validated with 47/50 stories on a live VM.\n' >> "$fixture/README.md"
if ! "$checker" "$fixture" >/dev/null 2>&1; then
    printf 'FAIL: checker rejected a story claim that its recorded run backs\n' >&2
    exit 1
fi

# A pass rate backed by a run that skipped stories is not a validated story
# claim. Mutate the writer-produced artifact so this exercises the same schema
# the production recorder emits rather than a hand-written JSON shape.
python3 - "$fixture/tests/evidence/story-runs/fixture-run.json" <<'PY'
import json
import sys

path = sys.argv[1]
run = json.loads(open(path).read())
run["totals"]["skipped"] = 1
open(path, "w").write(json.dumps(run, indent=2, sort_keys=True) + "\n")
PY
grep -q '"skipped": 1' "$fixture/tests/evidence/story-runs/fixture-run.json" || {
    printf 'FAIL: skipped-story mutation did not apply\n' >&2
    exit 1
}
assert_rejected 'story pass rate backed by skipped stories'
write_fixture_run ubuntu 50 47 ok

# Rate-limited stories are a separate diagnostic, but they are just as unable
# to support a published pass rate as skipped stories.
python3 - "$fixture/tests/evidence/story-runs/fixture-run.json" <<'PY'
import json
import sys

path = sys.argv[1]
run = json.loads(open(path).read())
run["totals"]["rate_limited"] = 1
open(path, "w").write(json.dumps(run, indent=2, sort_keys=True) + "\n")
PY
grep -q '"rate_limited": 1' "$fixture/tests/evidence/story-runs/fixture-run.json" || {
    printf 'FAIL: rate-limited-story mutation did not apply\n' >&2
    exit 1
}
assert_rejected 'story pass rate backed by rate-limited stories'
write_fixture_run ubuntu 50 47 ok

# Backed by a run, but attributed to a model that did not produce it.
sed -i 's|47/50 stories on a live VM.|47/50 stories on a live VM with gpt-4.1.|' "$fixture/README.md"
grep -q 'gpt-4.1' "$fixture/README.md" || {
    printf 'FAIL: model-attribution mutation did not apply\n' >&2
    exit 1
}
assert_rejected 'story pass rate attributed to the wrong model'
cp "$repo_root/README.md" "$fixture/README.md"

# A replay the harness declared unproven must not back a figure either. The
# artifact used to be written before the cassette audit ran, so a run that missed
# every call still produced a file with a healthy pass rate.
write_fixture_run ubuntu 50 47 failed
printf '\nUbuntu 24.04 is validated with 47/50 stories on a live VM.\n' >> "$fixture/README.md"
assert_rejected 'story pass rate from a replay whose cassette audit failed'
cp "$repo_root/README.md" "$fixture/README.md"

# A subset run must never back a headline: probes record an empty story_set.
write_fixture_run "" 4 4 ok
printf '\nUbuntu 24.04 is validated with 4/4 stories on a live VM.\n' >> "$fixture/README.md"
assert_rejected 'four-story probe quoted as a headline figure'
cp "$repo_root/README.md" "$fixture/README.md"
rm -f "$fixture/tests/evidence/story-runs/fixture-run.json"

# A claim file that vanishes must fail rather than quietly leave the checked set.
mv "$fixture/ROADMAP.md" "$fixture/ROADMAP.held"
assert_rejected 'a claim file missing from the checked surface'
mv "$fixture/ROADMAP.held" "$fixture/ROADMAP.md"

# The action count is derived from the catalogue source, so a retyped one fails.
actions="$(grep -oE '[0-9]+ typed actions' "$fixture/docs/introduction.md" | head -1 | grep -oE '^[0-9]+' || true)"
if [[ -z "$actions" ]]; then
    printf 'FAIL: could not find the typed-action count in the fixture\n' >&2
    exit 1
fi
sed -i "s/${actions} typed actions/999 typed actions/" "$fixture/docs/introduction.md"
assert_rejected 'action count that disagrees with the catalogue source'
cp "$repo_root/docs/introduction.md" "$fixture/docs/introduction.md"

# An ActionSpec qualifier must not exempt a stale subset count from evidence.
python3 - "$fixture/docs/developer-guide.md" <<'PYEOF'
import re
import sys
from pathlib import Path
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
updated, count = re.subn(
    r"[0-9]+ actions with an `ActionSpec`",
    "4 actions with an `ActionSpec`",
    text,
    count=1,
)
if count != 1:
    raise SystemExit("could not find the ActionSpec count in the fixture")
path.write_text(updated, encoding="utf-8")
PYEOF
assert_rejected_with_diagnostic \
    'ActionSpec count that disagrees with the generated table' \
    'developer-guide.md' 'claims 4 actions with an ActionSpec' 'derived'
cp "$repo_root/docs/developer-guide.md" "$fixture/docs/developer-guide.md"

# The generated-table reader must fail closed on an empty table and count rows exactly.
python3 - "$repo_root/scripts/check_evidence_claims.py" <<'PYEOF'
import importlib.util
import tempfile
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location("checker", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    docs = root / "docs"
    docs.mkdir()
    ref = docs / "action-reference.md"
    ref.write_text(
        "| Action | Command |\n|---|---|\n"
        "| `One` | `one` |\n| `Two2` | `two` |\n| `Three_3` | `three` |\n",
        encoding="utf-8",
    )
    if mod.count_action_specs(root) != 3:
        raise SystemExit("ActionSpec row fixture did not derive exactly 3")
    ref.write_text("| Action | Command |\n|---|---|\n", encoding="utf-8")
    try:
        mod.count_action_specs(root)
    except mod.Failure:
        pass
    else:
        raise SystemExit("empty ActionSpec table did not fail closed")
PYEOF

# No evidence at all must fail loudly rather than pass for lack of anything to
# compare against.
mv "$fixture/tests/evidence/workspace-tests.json" "$fixture/tests/evidence/held.json"
assert_rejected 'missing test-baseline artifact'
mv "$fixture/tests/evidence/held.json" "$fixture/tests/evidence/workspace-tests.json"

printf '\nFedora Workstation 44 is fully supported.\n' >> "$fixture/README.md"
assert_rejected 'plain Fedora fully supported'
cp "$repo_root/README.md" "$fixture/README.md"

# The same forbidden phrase, but in a file the shell guard never screened. Its
# claim_files list held 6 entries while CLAIM_FILES held 16, so ten files were
# unscreened and this mutation passed silently. Both lists now come from the
# Python module, so any file listed there is covered here.
printf '\nFedora Workstation 44 is fully supported.\n' >> "$fixture/docs/architecture.md"
assert_rejected 'forbidden claim in a file only the Python list knew about'
cp "$repo_root/docs/architecture.md" "$fixture/docs/architecture.md"

printf '\nlocal-clone path until npm publish lands\n' >> "$fixture/README.md"
assert_rejected 'publish-pending setup language'
cp "$repo_root/README.md" "$fixture/README.md"

sed -i '/sysknife approve <transaction-id>/d' "$fixture/assets/demo/mcp-flow-mock.sh"
assert_rejected 'MCP demo without terminal approval command'
cp "$repo_root/assets/demo/mcp-flow-mock.sh" "$fixture/assets/demo/mcp-flow-mock.sh"

# A story count written WITHOUT a pass/total slash used to be invisible: the
# story check only matched `N/M stories`, so "the full 65-story VM suite" sat in
# the introduction for months naming a suite that has never existed. The size has
# to match the stories on disk (whole suite or one family) or a recorded run.
printf '\nValidated with the full 65-story VM suite.\n' >> "$fixture/docs/introduction.md"
assert_rejected 'bare story count matching no suite and no run'
cp "$repo_root/docs/introduction.md" "$fixture/docs/introduction.md"

# ...and the counterpart: a real family size must still be quotable, or the guard
# would force every honest mention of the suite out of the docs.
printf '\nThe atomic family is 54 stories.\n' >> "$fixture/docs/introduction.md"
if ! "$checker" "$fixture" >/dev/null 2>&1; then
    printf 'FAIL: checker rejected a real family size (54 stories)\n' >&2
    exit 1
fi
cp "$repo_root/docs/introduction.md" "$fixture/docs/introduction.md"

# The tier rule, in both directions. Which releases may be called "Validated" is
# derived from the replay-verified pairs on disk, so the mutations have to attack
# the derivation rather than a hardcoded release name.
#
# 1. A release with no committed run at all. 20.04 is named in the install docs
#    as supported, which is exactly the kind of release someone would promote to
#    Validated by hand.
printf '\n| **Ubuntu 20.04 LTS** | apt family | full | **Validated** |\n' \
    >> "$fixture/docs/distro-support.md"
assert_rejected 'a release with no committed run tiered Validated'
cp "$repo_root/docs/distro-support.md" "$fixture/docs/distro-support.md"

# 2. A release whose record run is committed but whose replay is not. The pass
#    rate exists, nothing has reproduced it, and the parity gate never sees it —
#    so the tier is not earned. Deleting the replay twin must take the tier away
#    from a release the pristine fixture accepts, which also proves the rule is
#    reading the replay and not merely the presence of a file named for the
#    release.
rm -f "$fixture"/tests/evidence/story-runs/ubuntu-22.04-*.replay.json
assert_rejected 'a release tiered Validated with its record run but no replay'
cp "$repo_root"/tests/evidence/story-runs/*.json "$fixture/tests/evidence/story-runs/"

# 3. A replay twin that exists but did not reproduce the run. This is the shape
#    every LTS actually carried for a while: a `.replay.json` present and
#    `cassette_audit.verdict` `failed`, because the cassette kept only successes
#    and so could not reproduce a story whose first call the provider rejected.
#    The file's own fields say it did not reproduce anything; the tier said
#    Validated. Presence is not proof.
python3 - "$fixture/tests/evidence/story-runs" <<'PY'
import json, pathlib, sys
path = next(pathlib.Path(sys.argv[1]).glob("ubuntu-22.04-*.replay.json"))
run = json.loads(path.read_text())
run["cassette_audit"]["verdict"] = "failed"
run["cassette_audit"]["misses"] = 1
path.write_text(json.dumps(run, indent=2, sort_keys=True) + "\n")
PY
# The mutation has to have landed. A glob that matched nothing, or a run file
# that stopped carrying `cassette_audit`, would leave the fixture pristine and
# the assertion below would be testing the unmutated tree.
grep -q '"verdict": "failed"' "$fixture"/tests/evidence/story-runs/ubuntu-22.04-*.replay.json || {
    printf 'FAIL: replay-verdict mutation did not apply; fixture would pass vacuously\n' >&2
    exit 1
}
assert_rejected 'a release tiered Validated on a replay whose cassette audit failed'
cp "$repo_root"/tests/evidence/story-runs/*.json "$fixture/tests/evidence/story-runs/"

# A record with skipped stories cannot earn a Validated tier, even if its replay
# twin is otherwise healthy.
python3 - "$fixture/tests/evidence/story-runs/ubuntu-22.04-gpt-oss-120b.json" <<'PY'
import json
import sys

path = sys.argv[1]
run = json.loads(open(path).read())
run["totals"]["skipped"] = 1
open(path, "w").write(json.dumps(run, indent=2, sort_keys=True) + "\n")
PY
grep -q '"skipped": 1' "$fixture/tests/evidence/story-runs/ubuntu-22.04-gpt-oss-120b.json" || {
    printf 'FAIL: skipped-record tier mutation did not apply\n' >&2
    exit 1
}
assert_rejected 'Validated tier backed by a record with skipped stories'
cp "$repo_root/tests/evidence/story-runs/ubuntu-22.04-gpt-oss-120b.json" \
    "$fixture/tests/evidence/story-runs/ubuntu-22.04-gpt-oss-120b.json"

# Keep the diagnostic separate in the artifact contract too: a replay with a
# rate-limited story cannot validate a release.
python3 - "$fixture/tests/evidence/story-runs/ubuntu-22.04-gpt-oss-120b.replay.json" <<'PY'
import json
import sys

path = sys.argv[1]
run = json.loads(open(path).read())
run["totals"]["rate_limited"] = 1
open(path, "w").write(json.dumps(run, indent=2, sort_keys=True) + "\n")
PY
grep -q '"rate_limited": 1' \
    "$fixture/tests/evidence/story-runs/ubuntu-22.04-gpt-oss-120b.replay.json" || {
    printf 'FAIL: rate-limited-replay tier mutation did not apply\n' >&2
    exit 1
}
assert_rejected 'Validated tier backed by a replay with rate-limited stories'

printf 'Public claims contract passed.\n'
