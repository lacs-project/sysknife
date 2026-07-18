#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="$repo_root/tests/e2e/ubuntu-vm.sh"

bash -n "$script"

require_text() {
    local pattern="$1"
    if ! grep -Fq -- "$pattern" "$script"; then
        printf 'missing Ubuntu VM bootstrap contract: %s\n' "$pattern" >&2
        exit 1
    fi
}

require_text 'set -Eeuo pipefail'
require_text 'cloud-init-failed'
require_text 'Acquire::Retries=3'
require_text 'DPkg::Lock::Timeout=120'
require_text 'die "cloud-init bootstrap failed"'
require_text 'die "cloud-init did not complete within ${max_wait}s"'
require_text 'cloud-init completed without all required tools'

printf 'Ubuntu VM bootstrap contract passed.\n'
