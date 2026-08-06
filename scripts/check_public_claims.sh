#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# The helpers live next to this script, not inside the tree being checked: the
# mutation fixture in tests/release/public-claims.test.sh copies only claim files
# and evidence, so a path relative to repo_root would not resolve there.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

claim_files=(
    "$repo_root/README.md"
    "$repo_root/docs/introduction.md"
    "$repo_root/docs/quickstart.md"
    "$repo_root/docs/distro-support.md"
    "$repo_root/docs/contributing/ubuntu-vm-testing.md"
    "$repo_root/packages/setup/index.js"
)
demo_source="$repo_root/assets/demo/mcp-flow-mock.sh"

for path in "${claim_files[@]}" "$demo_source"; do
    if [[ ! -f "$path" ]]; then
        printf 'Public-claims input is missing: %s\n' "$path" >&2
        exit 1
    fi
done

reject_pattern() {
    local pattern="$1" message="$2"
    shift 2
    if grep -Eins -- "$pattern" "$@"; then
        printf 'Invalid public claim: %s\n' "$message" >&2
        exit 1
    fi
}

# Numeric claims — test counts, the action count, story pass rates — are checked
# against the artifacts that produced them by check_evidence_claims.py. This used
# to be a hand-maintained blacklist of stale ranges plus a required literal
# ("1,561 Rust tests"), which meant the guard itself had to be edited whenever
# reality moved, and it was not: the range stopped at 1,560 while the suite had
# grown to 1,681, so the docs, the guard, and the code all disagreed at once.
if ! python3 "$script_dir/check_evidence_claims.py" "$repo_root"; then
    printf 'Invalid public claim: a published figure does not derive from evidence\n' >&2
    exit 1
fi
reject_pattern 'until npm publish lands|publish[- ]pending' \
    'setup package is documented as unpublished' "${claim_files[@]}"
reject_pattern 'Fedora([^\n]|$)*(Workstation|Server)([^\n]|$)*fully supported|(Workstation|Server)([^\n]|$)*fully supported' \
    'plain Fedora requires the unfinished dnf action family' "${claim_files[@]}"
reject_pattern 'plan and approve from inside (Claude|chat)|chat approval is sufficient' \
    'MCP approval must be issued by the separate terminal command' "${claim_files[@]}"
reject_pattern 'words like "yes", "do it"|explicit approval, then execute' \
    'generated integrations must require terminal-issued receipts' "${claim_files[@]}"
# A table row *about* 22.04/26.04 whose final tier cell is "Validated" — covers
# both the bare `| 22.04 | … | validated |` (ubuntu-vm-testing.md) and the bolded
# `| **Ubuntu 22.04 LTS** | … | **Validated** |` (distro-support.md) shapes.
# grep -i makes it case-insensitive.
#
# The version has to appear in the row's FIRST cell — `[^|]*` before the first
# pipe. Matching it anywhere in the row made the 24.04 row unmentionable: citing
# "the committed run is 22.04" in its evidence cell tripped a rule about tiering,
# which would have pushed the honest wording out of the doc to appease the guard.
reject_pattern '^\|[^|]*(22\.04|26\.04)[^|]*\|.*\|[[:space:]]*\*{0,2}validated\*{0,2}[[:space:]]*\|' \
    'Ubuntu 22.04 and 26.04 are smoke-tested, not launch-validated' "${claim_files[@]}"

required_receipt_docs=(
    "$repo_root/README.md"
    "$repo_root/assets/demo/mcp-flow-mock.sh"
    "$repo_root/packages/setup/index.js"
)

for path in "${required_receipt_docs[@]}"; do
    if ! grep -Fq 'sysknife approve <transaction-id>' "$path"; then
        printf 'Receipt flow missing from %s: expected sysknife approve <transaction-id>\n' \
            "$path" >&2
        exit 1
    fi
done

printf 'Public claims are internally consistent.\n'
