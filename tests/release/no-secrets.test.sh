#!/usr/bin/env bash
# Guards scripts/check_no_secrets.sh in both directions.
#
# A secret scanner has two failure modes and the second one is what kills it:
#
#   1. missing a real credential — the obvious failure;
#   2. firing on this repo's legitimate fixtures, at which point somebody
#      disables it and it protects nothing.
#
# The repo genuinely contains `sk-ssh-ed25519` (an SSH *algorithm name*),
# `AKIAIOSFODNN7EXAMPLE` (AWS's published example), and a pile of short fake
# keys. So the whole tracked tree is scanned here and required to come back
# clean — that assertion is the reason the patterns are length-bounded rather
# than prefix-only.
#
# No real credential appears in this file. The positive cases are synthesised at
# the right length from a fixed filler character.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECK="$ROOT/scripts/check_no_secrets.sh"
[ -x "$CHECK" ] || { echo "FAIL: $CHECK not found or not executable"; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0

# --- 1. Real-shaped credentials must be caught ------------------------------
# Synthesised, never a live key: prefix + filler at the real body length.
make_key() { printf '%s%s' "$1" "$(head -c "$2" < /dev/zero | tr '\0' 'A')"; }

declare -a POSITIVES=(
    "$(make_key 'gsk_' 52)"          # Groq
    "$(make_key 'sk-' 48)"           # OpenAI classic
    "$(make_key 'sk-proj-' 64)"      # OpenAI project
    "$(make_key 'sk-ant-' 95)"       # Anthropic
    "$(make_key 'ghp_' 36)"          # GitHub PAT
    "$(make_key 'github_pat_' 82)"   # GitHub fine-grained
    "$(make_key 'AIza' 35)"          # Google
)
for key in "${POSITIVES[@]}"; do
    printf 'API_KEY = "%s"\n' "$key" > "$tmp/leak.txt"
    if "$CHECK" "$tmp/leak.txt" >/dev/null 2>&1; then
        echo "FAIL: a ${key:0:8}… credential ($(printf '%s' "$key" | wc -c) chars) was NOT caught"
        fail=1
    fi
done

# AWS keys are fixed-length, so the example and a real one are the same shape:
# only the exact-match allowlist separates them.
printf 'aws = "AKIA%s"\n' "0123456789ABCDEF" > "$tmp/aws.txt"
if "$CHECK" "$tmp/aws.txt" >/dev/null 2>&1; then
    echo "FAIL: an AWS access key was NOT caught"
    fail=1
fi

# --- 2. The repo's own fixtures must NOT be caught --------------------------
declare -a NEGATIVES=(
    'sk-ssh-ed25519'                  # SSH algorithm name, not a secret
    'sk-ecdsa-sha2-nistp256'          # ditto
    'sk-ant-test-key'
    'sk-proj-fake-key-for-testing'
    'ghp_abcdef1234567890'
    'ghp_abc123secrettoken'
    'sk-receipt-deadbeef'
    'AKIAIOSFODNN7EXAMPLE'            # AWS published example — allowlisted
)
for fixture in "${NEGATIVES[@]}"; do
    printf 'value = "%s"\n' "$fixture" > "$tmp/fixture.txt"
    if ! "$CHECK" "$tmp/fixture.txt" >/dev/null 2>&1; then
        echo "FAIL: legitimate fixture '$fixture' was flagged as a secret"
        fail=1
    fi
done

# --- 3. The whole tracked tree must be clean --------------------------------
# The assertion that keeps this scanner usable. If it ever fails, the answer is
# to shorten the offending fixture, not to loosen a pattern.
cd "$ROOT"
mapfile -t tracked < <(git ls-files)
if ! "$CHECK" "${tracked[@]}" >/dev/null 2>&1; then
    echo "FAIL: the tracked tree does not pass its own secret scan:"
    "$CHECK" "${tracked[@]}" 2>&1 | head -10
    fail=1
fi

# --- 4. It must never print the credential it found -------------------------
leak="$(make_key 'gsk_' 52)"
printf 'k = "%s"\n' "$leak" > "$tmp/echo.txt"
out="$("$CHECK" "$tmp/echo.txt" 2>&1 || true)"
if grep -qF "$leak" <<< "$out"; then
    echo "FAIL: the scanner echoed the credential it found — that is a second leak"
    fail=1
fi

# Mutation proof: point CHECK at a scanner that echoes the input and exits 1.
# The repaired assertion must detect the leaked credential despite pipefail.
mutant="$tmp/echoing-scanner.sh"
cat > "$mutant" <<'EOF'
#!/usr/bin/env bash
cat "$1"
exit 1
EOF
chmod +x "$mutant"
real_check="$CHECK"
CHECK="$mutant"
out="$("$CHECK" "$tmp/echo.txt" 2>&1 || true)"
if ! grep -qF "$leak" <<< "$out"; then
    echo "FAIL: the no-echo mutation did not make the assertion fail"
    fail=1
fi
CHECK="$real_check"

# --- 5. The pre-commit --staged path must fail closed -----------------------
staged_repo="$tmp/staged-repo"
mkdir -p "$staged_repo"
git -C "$staged_repo" init -q
git -C "$staged_repo" config user.name 'SysKnife test'
git -C "$staged_repo" config user.email 'sysknife-test@example.invalid'
printf 'clean\n' > "$staged_repo/README.md"
git -C "$staged_repo" add README.md
git -C "$staged_repo" commit -qm 'fixture baseline'

printf 'k = "%s"\n' "$leak" > "$staged_repo/leak.txt"
git -C "$staged_repo" add leak.txt
if staged_output="$(cd "$staged_repo" && "$CHECK" --staged 2>&1)"; then
    echo "FAIL: --staged accepted content that the explicit-file path rejects"
    fail=1
elif ! grep -Fq 'Refusing to commit' <<< "$staged_output"; then
    echo "FAIL: --staged did not report the staged finding"
    fail=1
fi

cp "$staged_repo/.git/index" "$staged_repo/index.good"
printf 'DIRT' > "$staged_repo/.git/index"
if git_error_output="$(cd "$staged_repo" && "$CHECK" --staged 2>&1)"; then
    echo "FAIL: --staged passed when git could not enumerate the index"
    fail=1
elif ! grep -Fq 'could not enumerate staged files' <<< "$git_error_output"; then
    echo "FAIL: --staged did not explain that staged-file enumeration failed"
    fail=1
fi
mv "$staged_repo/index.good" "$staged_repo/.git/index"

git -C "$staged_repo" reset -q HEAD -- leak.txt
rm -f "$staged_repo/leak.txt"
if empty_output="$(cd "$staged_repo" && "$CHECK" --staged 2>&1)"; then
    if [ -n "$empty_output" ]; then
        echo "FAIL: --staged printed output for an honest empty staged set"
        fail=1
    fi
else
    echo "FAIL: --staged rejected an honest empty staged set"
    fail=1
fi

# --- 6. A staged blob read failure must not masquerade as a finding ----------
fake_oid='1111111111111111111111111111111111111111'
git -C "$staged_repo" update-index --add --cacheinfo 100644,$fake_oid,unreadable.txt
if unreadable_output="$(cd "$staged_repo" && "$CHECK" --staged 2>&1)"; then
    echo "FAIL: --staged passed when git could not read staged bytes"
    fail=1
elif ! grep -Fq 'could not read staged bytes for unreadable.txt' <<< "$unreadable_output"; then
    echo "FAIL: --staged did not distinguish an unreadable staged blob"
    fail=1
elif grep -Fq 'staged content contains' <<< "$unreadable_output"; then
    echo "FAIL: unreadable staged bytes were reported as a credential finding"
    fail=1
fi
git -C "$staged_repo" update-index --force-remove unreadable.txt
if [ "$fail" != 0 ]; then exit 1; fi
echo "ok: catches real-shaped credentials, ignores this repo's fixtures"
echo "ok: the whole tracked tree scans clean, and findings never echo the secret"
