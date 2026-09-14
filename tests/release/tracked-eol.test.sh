#!/usr/bin/env bash
# Keep tracked text normalized in the Git index.
#
# A Windows or WSL checkout can otherwise follow contributor-specific line-ending
# settings. Without a repository policy, CRLF can enter the index. Some SysKnife
# tests compare generated documents byte-for-byte, so that corruption looks like
# an unrelated content failure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if ! eol="$(git ls-files --eol)"; then
    echo "FAIL: could not inspect tracked file line endings" >&2
    exit 1
fi

bad="$(printf '%s\n' "$eol" | grep -E '^i/(crlf|mixed)[[:space:]]' || true)"
if [ -n "$bad" ]; then
    echo "FAIL: tracked files contain CRLF or mixed line endings in the Git index:" >&2
    printf '%s\n' "$bad" >&2
    exit 1
fi

echo "ok: tracked Git index contains no CRLF or mixed line endings"
