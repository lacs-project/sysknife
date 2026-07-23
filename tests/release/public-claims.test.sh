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
    "docs/introduction.md"
    "docs/quickstart.md"
    "docs/distro-support.md"
    "docs/contributing/ubuntu-vm-testing.md"
    "packages/setup/index.js"
    "assets/demo/mcp-flow-mock.sh"
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

sed -i 's/1,403 Rust tests/1,256 Rust tests/' "$fixture/README.md"
assert_rejected 'old test count'
cp "$repo_root/README.md" "$fixture/README.md"

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
