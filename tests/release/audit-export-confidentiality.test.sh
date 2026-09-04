#!/usr/bin/env bash
#
# audit-export-confidentiality.test.sh — `sysknife audit export` moves signed
# chain rows out of a 0600 database, and every row carries `request_hash`, an
# unsalted SHA-256 over the UNREDACTED params. The docs have to say so.
#
# The export docs enumerated what the format omits (argv, outcome, a separate
# signature) and said nothing about what it carries, which reads as a redacted
# artifact to anyone skimming. See issue #268.
#
# The doc claim rests on one code fact: the hash is computed before redaction.
# This check derives that fact from dispatcher.rs rather than restating it, so
# if someone ever moves `redact_params` above `compute_request_hash` the docs
# become wrong and this fails, instead of the docs quietly outliving the code.
#
# Host-side only: greps files, no daemon, no network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
dispatcher="$repo_root/crates/sysknife-daemon/src/dispatcher.rs"
cli_doc="$repo_root/docs/cli.md"
chain_doc="$repo_root/docs/the-audit-chain.md"

for f in "$dispatcher" "$cli_doc" "$chain_doc"; do
    [ -f "$f" ] || { printf 'FAIL: missing file: %s\n' "$f" >&2; exit 1; }
done

failures=0
report() { printf 'FAIL  %s\n' "$1" >&2; failures=$((failures + 1)); }

# The code fact. An empty line number is a failure, not a pass over nothing.
hash_line="$(grep -n 'let request_hash = compute_request_hash(' "$dispatcher" | head -1 | cut -d: -f1 || true)"
redact_line="$(grep -n 'let redacted_params = redact_params(' "$dispatcher" | head -1 | cut -d: -f1 || true)"

if [ -z "$hash_line" ] || [ -z "$redact_line" ]; then
    printf 'FAIL: cannot locate compute_request_hash / redact_params in %s\n' "$dispatcher" >&2
    exit 1
fi

if [ "$hash_line" -ge "$redact_line" ]; then
    printf 'NOTE: redaction now precedes the request hash (%s:%s before %s).\n' \
        "$dispatcher" "$redact_line" "$hash_line" >&2
    printf 'The export confidentiality wording is derived from the opposite order; update both.\n' >&2
    exit 1
fi

# The docs must name the exposure, not merely mention export.
grep -Fq 'not a redacted artifact' "$cli_doc" \
    || report "docs/cli.md does not state that an export is not a redacted artifact"
grep -Fq 'request_hash' "$cli_doc" \
    || report "docs/cli.md does not name request_hash in the export section"
grep -Fq 'unredacted' "$cli_doc" \
    || report "docs/cli.md does not say the hash commits to unredacted parameters"

grep -Fq 'redacted artifact' "$chain_doc" \
    || report "docs/the-audit-chain.md does not state the export confidentiality class"
grep -Fq 'request_hash' "$chain_doc" \
    || report "docs/the-audit-chain.md does not name request_hash"

if [ "$failures" -ne 0 ]; then
    printf '\n%d audit-export confidentiality failure(s).\n' "$failures" >&2
    exit 1
fi

printf 'audit export confidentiality stated in docs/cli.md and docs/the-audit-chain.md (hash at line %s precedes redaction at %s).\n' \
    "$hash_line" "$redact_line"
