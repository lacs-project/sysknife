#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

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

# Any count below the current baseline is stale. The range must be widened
# whenever the baseline moves: it once stopped at 1,347 while reality was at
# 1,490, so the guard sat green through 85 tests of drift.
#
# The baseline counts the WHOLE workspace — exactly what
# `cargo nextest run --workspace --locked` prints — so a reader can verify it
# with one command. Quoting a subset (e.g. excluding the GUI crate) makes the
# number unverifiable from the documented command, which is how it silently
# came to mean two different things.
reject_pattern '1,(2[0-9][0-9]|3[0-9][0-9]|4[0-9][0-9]|5[0-5][0-9]|56[0-0])( Rust)? tests' \
    'test count is stale; the release baseline is 1,561 Rust tests' \
    "${claim_files[@]}"
reject_pattern 'until npm publish lands|publish[- ]pending' \
    'setup package is documented as unpublished' "${claim_files[@]}"
reject_pattern 'Fedora([^\n]|$)*(Workstation|Server)([^\n]|$)*fully supported|(Workstation|Server)([^\n]|$)*fully supported' \
    'plain Fedora requires the unfinished dnf action family' "${claim_files[@]}"
reject_pattern 'plan and approve from inside (Claude|chat)|chat approval is sufficient' \
    'MCP approval must be issued by the separate terminal command' "${claim_files[@]}"
reject_pattern 'words like "yes", "do it"|explicit approval, then execute' \
    'generated integrations must require terminal-issued receipts' "${claim_files[@]}"
# A 22.04/26.04 table row whose final tier cell is "Validated" — covers both
# the bare `| 22.04 | … | validated |` (ubuntu-vm-testing.md) and the bolded
# `| **Ubuntu 22.04 LTS** | … | **Validated** |` (distro-support.md) shapes.
# grep -i makes it case-insensitive; the trailing-cell anchor avoids matching
# prose or the legitimately Validated 24.04 row.
reject_pattern '(22\.04|26\.04).*\|[[:space:]]*\*{0,2}validated\*{0,2}[[:space:]]*\|' \
    'Ubuntu 22.04 and 26.04 are smoke-tested, not launch-validated' "${claim_files[@]}"

required_receipt_docs=(
    "$repo_root/README.md"
    "$repo_root/assets/demo/mcp-flow-mock.sh"
    "$repo_root/packages/setup/index.js"
)

required_test_count_docs=(
    "$repo_root/README.md"
    "$repo_root/docs/introduction.md"
    "$repo_root/docs/distro-support.md"
)
for path in "${required_test_count_docs[@]}"; do
    if ! grep -Fq '1,561 Rust tests' "$path"; then
        printf 'Verified test baseline missing from %s: expected 1,561 Rust tests\n' \
            "$path" >&2
        exit 1
    fi
done

for path in "${required_receipt_docs[@]}"; do
    if ! grep -Fq 'sysknife approve <transaction-id>' "$path"; then
        printf 'Receipt flow missing from %s: expected sysknife approve <transaction-id>\n' \
            "$path" >&2
        exit 1
    fi
done

printf 'Public claims are internally consistent.\n'
