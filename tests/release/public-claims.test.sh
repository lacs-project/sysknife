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
# would make every assert_rejected below pass vacuously. Keep this list in sync
# with claim_files/demo_source in check_public_claims.sh.
fixture_files=(
    "README.md"
    "ROADMAP.md"
    "docs/introduction.md"
    "docs/quickstart.md"
    "docs/distro-support.md"
    "docs/contributing/ubuntu-vm-testing.md"
    "docs/contributing/testing.md"
    "packages/setup/index.js"
    "assets/demo/mcp-flow-mock.sh"
    # Evidence the numeric claims derive from, and the source the action count is
    # counted out of. Without these the checker aborts on its own input check and
    # every assert_rejected below would pass for the wrong reason.
    "tests/evidence/workspace-tests.json"
    "crates/sysknife-brain/src/planning_tools/propose_plan.rs"
    # The committed story run that backs the published pass rate. Without it the
    # pristine fixture fails, because README's figure would have no evidence — the
    # guard working, but on the fixture rather than on a real claim.
    "tests/evidence/story-runs/ubuntu-22.04-gpt-oss-120b.json"
)
for rel in "${fixture_files[@]}"; do
    mkdir -p "$fixture/$(dirname "$rel")"
    cp "$repo_root/$rel" "$fixture/$rel"
done

# Guard against re-introducing the vacuous-fixture bug: the pristine copy must
# PASS, proving rejections below come from the mutation, not a missing input.
if ! "$checker" "$fixture" >/dev/null 2>&1; then
    printf 'FAIL: pristine fixture rejected — fixture is incomplete\n' >&2
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
actions="$(grep -oE '[0-9]+ typed actions' "$fixture/docs/introduction.md" | head -1 | grep -oE '^[0-9]+')"
if [[ -z "$actions" ]]; then
    printf 'FAIL: could not find the typed-action count in the fixture\n' >&2
    exit 1
fi
sed -i "s/${actions} typed actions/999 typed actions/" "$fixture/docs/introduction.md"
assert_rejected 'action count that disagrees with the catalogue source'
cp "$repo_root/docs/introduction.md" "$fixture/docs/introduction.md"

# No evidence at all must fail loudly rather than pass for lack of anything to
# compare against.
mv "$fixture/tests/evidence/workspace-tests.json" "$fixture/tests/evidence/held.json"
assert_rejected 'missing test-baseline artifact'
mv "$fixture/tests/evidence/held.json" "$fixture/tests/evidence/workspace-tests.json"

printf '\nFedora Workstation 44 is fully supported.\n' >> "$fixture/README.md"
assert_rejected 'plain Fedora fully supported'
cp "$repo_root/README.md" "$fixture/README.md"

printf '\nlocal-clone path until npm publish lands\n' >> "$fixture/README.md"
assert_rejected 'publish-pending setup language'
cp "$repo_root/README.md" "$fixture/README.md"

sed -i '/sysknife approve <transaction-id>/d' "$fixture/assets/demo/mcp-flow-mock.sh"
assert_rejected 'MCP demo without terminal approval command'
cp "$repo_root/assets/demo/mcp-flow-mock.sh" "$fixture/assets/demo/mcp-flow-mock.sh"

# Flip the bolded 22.04 launch-matrix tier to Validated — the guard must reject
# it even in distro-support.md's `**Ubuntu 22.04 LTS** … **Validated**` shape.
sed -i '/Ubuntu 22\.04 LTS/ s/\*\*Smoke-tested\*\*/**Validated**/' \
    "$fixture/docs/distro-support.md"
assert_rejected 'Ubuntu 22.04 marked validated in bolded launch matrix'
cp "$repo_root/docs/distro-support.md" "$fixture/docs/distro-support.md"

printf 'Public claims contract passed.\n'
