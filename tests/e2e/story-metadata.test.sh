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
derived_count="$(printf '%s\n' "$metadata" | grep -c .)"
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
ubuntu_count="$(printf '%s\n' "$metadata" | awk -F'\t' '$2 == "ubuntu"' | grep -c .)"
atomic_count="$(printf '%s\n' "$metadata" | awk -F'\t' '$2 == "atomic"' | grep -c .)"
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
trap 'rm -rf "$mutant"' EXIT
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

if [ "$failures" -ne 0 ]; then
    printf '\n%d story-metadata failure(s).\n' "$failures" >&2
    exit 1
fi

printf 'Story metadata derived cleanly: %d stories (%d ubuntu, %d atomic).\n' \
    "$derived_count" "$ubuntu_count" "$atomic_count"
