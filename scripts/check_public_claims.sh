#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# The helpers live next to this script, not inside the tree being checked: the
# mutation fixture in tests/release/public-claims.test.sh copies only claim files
# and evidence, so a path relative to repo_root would not resolve there.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Read out of check_evidence_claims.py rather than kept here as a second copy.
# The two lists drifted -- this one had 6 entries, the Python one 16 -- so ten
# files carrying public claims were never screened by the prose rules below.
# tests/release/public-claims.test.sh already reads the list the same way.
mapfile -t claim_files_rel < <(
    python3 - "$script_dir/check_evidence_claims.py" <<'PYEOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("checker", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print("\n".join(mod.CLAIM_FILES))
PYEOF
)

# `set -euo pipefail` does not see a failure inside process substitution, so a
# rename in check_evidence_claims.py would leave this list empty and the script
# would exit 0 having screened nothing.
((${#claim_files_rel[@]})) || {
    echo 'could not read CLAIM_FILES from check_evidence_claims.py' >&2
    exit 1
}

claim_files=()
for rel in "${claim_files_rel[@]}"; do
    claim_files+=("$repo_root/$rel")
done
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
# Which releases may be tiered "Validated" is decided by check_evidence_claims.py
# (check_validated_tiers), from the replay-verified artifact pairs on disk.
#
# It used to be this, a literal list:
#
#   reject_pattern '^\|[^|]*(22\.04|26\.04)[^|]*\|.*\|…validated…\|' \
#       'Ubuntu 22.04 and 26.04 are smoke-tested, not launch-validated'
#
# which is the same hand-maintained blacklist the numeric guards above were
# rewritten to remove, and it aged worse than stale. 22.04 accumulated five live
# runs and a committed replay pair, so the guard started forbidding the accurate
# tier, leaving only two ways to go green: understate the evidence, or delete the
# rule. Deriving the permitted set keeps the rule's actual purpose — aspiration
# must not be published as fact — while letting a release earn its tier by having
# a run committed rather than by someone remembering to edit a script.

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
