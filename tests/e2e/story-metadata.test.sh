#!/usr/bin/env bash
#
# story-metadata.test.sh — the story table must be derived from the story files,
# and the derivation must fail loudly rather than skip what it cannot read.
#
# `run-stories.sh` used to carry a 54-entry STORY_NAMES table alongside the 104
# story files. It had already drifted: the table stopped at 54, so every one of
# the 50 Ubuntu stories printed as a bare "Story 73" with no name in every
# results table ever published, and the documented full run spelled its story set
# as the hand-typed range `$(seq 55 104)`.
#
# This test asserts on `run-stories.sh --metadata` — the real parser — rather
# than reimplementing the header regex. A second parser would be a second answer.
#
# Host-side only: no VM, no daemon, no network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="$repo_root/tests/e2e/run-stories.sh"
story_dir="$repo_root/tests/e2e/stories"

failures=0
report() {
    printf 'FAIL  %s\n' "$1" >&2
    failures=$((failures + 1))
}

[ -x "$runner" ] || { printf 'missing runner: %s\n' "$runner" >&2; exit 1; }

metadata="$(bash "$runner" --metadata)"
derived_count="$(printf '%s\n' "$metadata" | grep -c . || true)"
file_count="$(find "$story_dir" -maxdepth 1 -name 'story-*.sh' | wc -l)"

# A regex that quietly matched nothing would make every assertion below vacuous.
if [ "$file_count" -lt 100 ]; then
    report "only $file_count story files found; the glob has drifted"
fi
if [ "$derived_count" -ne "$file_count" ]; then
    report "derived $derived_count stories from $file_count files — the parser is dropping some"
fi

# Every derived id must name a real file, and the id in the header must match the
# id in the filename. A copy-pasted header (story-73.sh opening "# Story 37")
# would otherwise mislabel results and land one story's name on another.
while IFS=$'\t' read -r id family name; do
    [ -n "$id" ] || continue
    if [ ! -f "$story_dir/story-$id.sh" ]; then
        report "derived story $id has no story-$id.sh"
        continue
    fi
    header_id="$(sed -n '2p' "$story_dir/story-$id.sh" | sed -nE 's/^# Story ([0-9]+).*/\1/p')"
    if [ "$header_id" != "$id" ]; then
        report "story-$id.sh header claims story $header_id"
    fi
    case "$family" in
        ubuntu | atomic) ;;
        *) report "story $id has unknown family '$family'" ;;
    esac
    if [ -z "$name" ]; then
        report "story $id derived an empty name"
    fi
done <<< "$metadata"

# Both families must be populated: a filter that silently classified everything
# one way would still satisfy the count check above.
ubuntu_count="$(printf '%s\n' "$metadata" | awk -F'\t' '$2 == "ubuntu"' | grep -c . || true)"
atomic_count="$(printf '%s\n' "$metadata" | awk -F'\t' '$2 == "atomic"' | grep -c . || true)"
if [ "$ubuntu_count" -lt 1 ] || [ "$atomic_count" -lt 1 ]; then
    report "family split is degenerate: $ubuntu_count ubuntu, $atomic_count atomic"
fi

# The two families must partition the ids contiguously: atomic first, then
# ubuntu. Checking only that both are non-empty would let a story that lost its
# `ubuntu` tag fall into the atomic family, which is the set that
# SYSKNIFE_ALLOW_DESTRUCTIVE=1 runs by default. Contiguity pins the partition
# without restating either count, so adding a story to either end still passes.
atomic_max="$(printf '%s\n' "$metadata" | awk -F'\t' '$2 == "atomic" {print $1}' | sort -n | tail -1)"
ubuntu_min="$(printf '%s\n' "$metadata" | awk -F'\t' '$2 == "ubuntu" {print $1}' | sort -n | head -1)"
if [ -n "$atomic_max" ] && [ -n "$ubuntu_min" ] && [ "$ubuntu_min" -le "$atomic_max" ]; then
    report "families interleave: ubuntu starts at $ubuntu_min but atomic runs to $atomic_max"
fi
atomic_ids="$(printf '%s\n' "$metadata" | awk -F'\t' '$2 == "atomic" {print $1}' | sort -n)"
expected_atomic="$(seq 1 "$atomic_count")"
if [ "$atomic_ids" != "$expected_atomic" ]; then
    report "the atomic family is not the contiguous range 1..$atomic_count; a story may have lost its ubuntu tag"
fi

duplicates="$(printf '%s\n' "$metadata" | cut -f1 | sort | uniq -d)"
if [ -n "$duplicates" ]; then
    report "duplicate story ids derived: $(printf '%s' "$duplicates" | tr '\n' ' ')"
fi

# Mutation: an unreadable header must stop the run. If the parser skipped it
# instead, a story could drop out of the suite without a word — which is the
# failure mode the old hand-maintained table had.
mutant="$(mktemp -d)"
fakeroot="$(mktemp -d)"
trap 'rm -rf "$mutant" "$fakeroot"' EXIT
cp "$runner" "$mutant/run-stories.sh"
cp -r "$story_dir" "$mutant/stories"
printf '#!/usr/bin/env bash\n# this header says nothing about a story\nexit 0\n' \
    > "$mutant/stories/story-9999.sh"
if bash "$mutant/run-stories.sh" --metadata >/dev/null 2>&1; then
    report "an unparseable story header did not fail the derivation"
fi

# ...and the pristine copy must still pass, or the mutation above proved nothing.
rm -f "$mutant/stories/story-9999.sh"
if ! bash "$mutant/run-stories.sh" --metadata >/dev/null 2>&1; then
    report "the unmutated copy also fails — the mutation result is meaningless"
fi

# #252: an unrecognised tag must fail, not silently reclassify. A typo like
# `ubunut` used to move an ubuntu story into the atomic family with no word
# from either parser, shifting the family counts the evidence guard derives.
cp "$story_dir/story-63.sh" "$mutant/stories/story-9999.sh"
sed -i '2s/.*/# Story 9999 (ubunut, read-only): Typo family/' \
    "$mutant/stories/story-9999.sh"
if ! grep -Fq '# Story 9999 (ubunut, read-only)' \
    "$mutant/stories/story-9999.sh"; then
    report "unknown-tag mutation did not apply — the assertion below is vacuous"
fi
if bash "$mutant/run-stories.sh" --metadata >/dev/null 2>&1; then
    report "an unrecognised story tag did not fail the derivation"
fi
tag_diag="$(bash "$mutant/run-stories.sh" --metadata 2>&1 || true)"
case "$tag_diag" in
    *story-9999.sh*ubunut*) ;;
    *) report "unknown-tag failure did not name the file/tag: $tag_diag" ;;
esac

# ...and the pristine copy must still pass, or the mutation above proved nothing.
rm -f "$mutant/stories/story-9999.sh"
if ! bash "$mutant/run-stories.sh" --metadata >/dev/null 2>&1; then
    report "the unmutated copy also fails — the unknown-tag result is meaningless"
fi

# #390: the vocabulary is per-word, so a combination of known words that does
# not exist in the tree today — `(ubuntu, destructive)` is exactly that — is
# perfectly meaningful and must be derived, not rejected. A whole-string
# whitelist fails CI on it until somebody edits a `case` arm, which is the
# brittleness in the direction this repository grows that #390 names.
cp "$story_dir/story-63.sh" "$mutant/stories/story-9999.sh"
sed -i '2s/.*/# Story 9999 (ubuntu, destructive): New combination/' \
    "$mutant/stories/story-9999.sh"
if ! bash "$mutant/run-stories.sh" --metadata >/dev/null 2>&1; then
    report "a valid new tag combination was rejected by the vocabulary"
fi
combo_family="$(bash "$mutant/run-stories.sh" --metadata 2>/dev/null \
    | awk -F'\t' '$1 == "9999" { print $2 }')"
if [ "$combo_family" != ubuntu ]; then
    report "story 9999 (ubuntu, destructive) derived family '$combo_family', expected ubuntu"
fi
rm -f "$mutant/stories/story-9999.sh"

# #252: the grammar says the Story header lives on line 2. A valid header
# shifted to line 3 must fail rather than derive a row from the wrong line.
cp "$story_dir/story-63.sh" "$mutant/stories/story-9999.sh"
sed -i '2s/.*/# Story 9999 (ubuntu, read-only): Shifted header/' \
    "$mutant/stories/story-9999.sh"
sed -i '1i # fixture: this line pushes the header to line 3' \
    "$mutant/stories/story-9999.sh"
if sed -n '2p' "$mutant/stories/story-9999.sh" | grep -q '^# Story'; then
    report "line-3 mutation did not move the header off line 2"
fi
if bash "$mutant/run-stories.sh" --metadata >/dev/null 2>&1; then
    report "a story header moved off line 2 did not fail the derivation"
fi

# ...and the pristine copy must still pass, or the mutation above proved nothing.
rm -f "$mutant/stories/story-9999.sh"
if ! bash "$mutant/run-stories.sh" --metadata >/dev/null 2>&1; then
    report "the unmutated copy also fails — the line-3 result is meaningless"
fi

# #252: the Python evidence checker derives families by delegating to this same
# runner, so every rejection above must surface through that path too — with the
# canonical parser's own diagnostic, not a second Python grammar. The fake root
# mirrors the layout story_family_sizes() expects (tests/e2e/run-stories.sh).
mkdir -p "$fakeroot/tests/e2e/stories"
cp "$runner" "$fakeroot/tests/e2e/run-stories.sh"
cp "$story_dir"/story-*.sh "$fakeroot/tests/e2e/stories/"
python_consumer() {
    python3 - "$fakeroot" "$repo_root/scripts/check_evidence_claims.py" <<'PYEOF'
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("checker", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
try:
    sizes = mod.story_family_sizes(Path(sys.argv[1]))
except mod.Failure as exc:
    print(f"FAILURE: {exc}")
    raise SystemExit(10)
print(f"OK: ubuntu={sizes['ubuntu']} atomic={sizes['atomic']}")
PYEOF
}

# Pristine tree: the consumer must agree with the runner, derived not retyped.
consumer_ok="$(python_consumer 2>&1)" || {
    report "the Python consumer rejected the pristine tree: $consumer_ok"
    consumer_ok=""
}
if [ -n "${consumer_ok:-}" ]; then
    case "$consumer_ok" in
        *"OK: ubuntu=$ubuntu_count atomic=$atomic_count"*) ;;
        *) report "consumer disagrees with the runner: $consumer_ok" ;;
    esac
fi

# Unknown tag through the delegation path: Python must reject it because the
# one parser rejected it, naming the file and the bad tag.
cp "$story_dir/story-63.sh" "$fakeroot/tests/e2e/stories/story-9999.sh"
sed -i '2s/.*/# Story 9999 (ubunut, read-only): Typo family/' \
    "$fakeroot/tests/e2e/stories/story-9999.sh"
if consumer_out="$(python_consumer 2>&1)"; then
    report "the Python consumer accepted an unrecognised story tag"
    consumer_out=""
fi
if [ -n "${consumer_out:-}" ]; then
    case "$consumer_out" in
        *story-9999.sh*ubunut*) ;;
        *) report "consumer unknown-tag failure did not name the file/tag: $consumer_out" ;;
    esac
fi
rm -f "$fakeroot/tests/e2e/stories/story-9999.sh"

# Header on line 3 through the delegation path.
cp "$story_dir/story-63.sh" "$fakeroot/tests/e2e/stories/story-9999.sh"
sed -i '2s/.*/# Story 9999 (ubuntu, read-only): Shifted header/' \
    "$fakeroot/tests/e2e/stories/story-9999.sh"
sed -i '1i # fixture: this line pushes the header to line 3' \
    "$fakeroot/tests/e2e/stories/story-9999.sh"
if consumer_out="$(python_consumer 2>&1)"; then
    report "the Python consumer accepted a header moved off line 2"
    consumer_out=""
fi
if [ -n "${consumer_out:-}" ]; then
    case "$consumer_out" in
        *story-9999.sh*) ;;
        *) report "consumer line-3 failure did not name the file: $consumer_out" ;;
    esac
fi
rm -f "$fakeroot/tests/e2e/stories/story-9999.sh"
consumer_ok="$(python_consumer 2>&1)" || {
    report "the restored fixture is rejected — the mutation results are meaningless"
}

# Delegation negative controls: the consumer must fail loudly when the
# canonical surface itself is unusable, never read it as "zero stories". The
# repo has had guards go green over an empty set; an empty family table here
# would let every bare-count claim pass vacuously.
assert_consumer_fails() {
    local label="$1"
    local output
    if output="$(python_consumer 2>&1)"; then
        report "the Python consumer went green over $label: $output"
    elif [ -z "$output" ]; then
        report "the Python consumer failed silently over $label"
    fi
}
mv "$fakeroot/tests/e2e/run-stories.sh" "$fakeroot/tests/e2e/run-stories.held"
assert_consumer_fails "a missing canonical runner"
mv "$fakeroot/tests/e2e/run-stories.held" "$fakeroot/tests/e2e/run-stories.sh"
printf '#!/usr/bin/env bash\nexit 3\n' > "$fakeroot/tests/e2e/run-stories.sh"
assert_consumer_fails "a canonical runner that exits non-zero"
printf '#!/usr/bin/env bash\nexit 0\n' > "$fakeroot/tests/e2e/run-stories.sh"
assert_consumer_fails "empty metadata over a non-empty story tree"
printf '#!/usr/bin/env bash\nprintf "this is not a metadata row\\n"\n' \
    > "$fakeroot/tests/e2e/run-stories.sh"
assert_consumer_fails "a malformed metadata row"
printf '#!/usr/bin/env bash\nprintf "9999\\tmint\\tTypo family\\n"\n' \
    > "$fakeroot/tests/e2e/run-stories.sh"
assert_consumer_fails "an unknown family value"
cp "$runner" "$fakeroot/tests/e2e/run-stories.sh"
consumer_ok="$(python_consumer 2>&1)" || {
    report "the restored canonical runner is rejected — the control results are meaningless"
}

if [ "$failures" -ne 0 ]; then
    printf '\n%d story-metadata failure(s).\n' "$failures" >&2
    exit 1
fi

printf 'Story metadata derived cleanly: %d stories (%d ubuntu, %d atomic).\n' \
    "$derived_count" "$ubuntu_count" "$atomic_count"
