#!/usr/bin/env bash
#
# check_no_secrets.sh — refuse to commit a provider credential.
#
# A key that reaches a commit is in the history whether or not the commit is
# ever pushed, and rewriting published history is a far worse day than being
# stopped here. CI already runs TruffleHog, but only on `pull_request` and only
# with --only-verified: a direct push to main is not scanned until the weekly
# sweep, and a revoked-but-real key verifies as nothing and passes. This runs
# before the commit object exists, needs no network, and does not care whether
# the credential is still live — a dead key in the history is still a leak of
# the account it belonged to.
#
# Usage:
#   check_no_secrets.sh --staged     # what `git commit` is about to record
#   check_no_secrets.sh <file>...    # explicit files
#
# ── Why the patterns are length-bounded ─────────────────────────────────────
#
# Prefix alone is useless here. This repo legitimately contains:
#
#   sk-ssh-ed25519, sk-ecdsa-sha2-nistp256   SSH *algorithm names*, not secrets
#   sk-ant-test-key, ghp_abcdef1234567890    obvious test fixtures
#   AKIAIOSFODNN7EXAMPLE                     AWS's own documentation example
#
# A bare `sk-` or `ghp_` rule would reject every one of those and be turned off
# within a day. Real credentials are long and high-entropy; the fixtures above
# are short. So each pattern carries the real format's minimum body length, and
# the few documented example values that are genuinely long are allowlisted by
# exact match.
set -euo pipefail

# Literal values that look like credentials and are published as examples by
# their own vendors. Exact matches only — never a prefix.
ALLOWED_EXAMPLES=(
    "AKIAIOSFODNN7EXAMPLE"                      # AWS docs, every IAM example
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # its matching secret
)

# provider:regex. Bodies are sized to the real format so fixtures fall short.
PATTERNS=(
    "Groq:gsk_[A-Za-z0-9]{40,}"
    "OpenAI:sk-[A-Za-z0-9]{40,}"
    "OpenAI project:sk-proj-[A-Za-z0-9_-]{40,}"
    "Anthropic:sk-ant-[A-Za-z0-9_-]{40,}"
    "GitHub PAT:ghp_[A-Za-z0-9]{36,}"
    "GitHub fine-grained PAT:github_pat_[A-Za-z0-9_]{60,}"
    "AWS access key:AKIA[0-9A-Z]{16}"
    "Google API key:AIza[A-Za-z0-9_-]{35,}"
    "Slack token:xox[baprs]-[A-Za-z0-9-]{20,}"
)

scan_text() {
    # $1 = human label for the source, stdin = content
    local source="$1" content found=0
    content="$(cat)"
    for entry in "${PATTERNS[@]}"; do
        local provider="${entry%%:*}" regex="${entry#*:}"
        while IFS= read -r hit; do
            [ -n "$hit" ] || continue
            local allowed=0
            for example in "${ALLOWED_EXAMPLES[@]}"; do
                [ "$hit" = "$example" ] && allowed=1 && break
            done
            [ "$allowed" = 1 ] && continue
            # Never echo the credential: prefix and length are enough to find it.
            printf 'SECRET: %s key in %s — starts %s…, %d chars\n' \
                "$provider" "$source" "${hit:0:7}" "${#hit}" >&2
            found=1
        done < <(printf '%s' "$content" | grep -oE "$regex" || true)
    done
    return "$found"
}

status=0
if [ "${1:-}" = "--staged" ]; then
    # The staged content itself, not the working tree: those differ, and it is
    # the staged bytes that become the commit.
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        git show ":$path" 2>/dev/null | scan_text "staged $path" || status=1
    done < <(git diff --cached --name-only --diff-filter=ACMR)
else
    for path in "$@"; do
        [ -f "$path" ] || continue
        scan_text "$path" < "$path" || status=1
    done
fi

if [ "$status" != 0 ]; then
    cat >&2 <<'MSG'

Refusing to commit: the staged content contains what looks like a live
provider credential.

If it is real: remove it, then ROTATE it — assume it is already compromised.
Keep credentials outside the repo (an env var, or a 0600 file in ~/.config).

If it is a test fixture, shorten it. Real keys are long; every fixture in this
repo is short enough that these patterns ignore it. Do not lengthen the
patterns to accommodate a realistic-looking fake.
MSG
fi
exit "$status"
