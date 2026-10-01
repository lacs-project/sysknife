#!/usr/bin/env bash
# Offline contract tests: no GitHub credentials or network access.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/repo/.github/workflows"
export PATH="$tmp/bin:$PATH" PIN_API_LOG="$tmp/api.log"
cat > "$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$2" >> "$PIN_API_LOG"
case "$2" in
  repos/actions/checkout/git/ref/tags/v1.2.3) echo 'commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ;;
  repos/actions/checkout/git/ref/tags/v9.9.9) echo 'commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' ;;
  repos/github/codeql-action/git/ref/tags/v4.37.9) echo 'tag cccccccccccccccccccccccccccccccccccccccc' ;;
  repos/github/codeql-action/git/tags/cccccccccccccccccccccccccccccccccccccccc) echo 'tag dddddddddddddddddddddddddddddddddddddddd' ;;
  repos/github/codeql-action/git/tags/dddddddddddddddddddddddddddddddddddddddd) echo 'commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ;;
  *) echo 'HTTP 404 or API unavailable (fixture)' >&2; exit 1 ;;
esac
STUB
chmod +x "$tmp/bin/gh"
workflow="$tmp/repo/.github/workflows/test.yaml"
cat > "$workflow" <<'YAML'
jobs:
  test:
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1.2.3
      - uses:    github/codeql-action/analyze@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4.37.9
      - uses:
          actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1.2.3
      - {uses: 'actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', name: 'quoted # text'} # v1.2.3
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # stable (branch)
      - uses: ./.github/actions/local
      - run: |
          echo 'uses: fake/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
YAML
check() { bash "$root/scripts/verify-action-pins.sh" "$tmp/repo" > "$tmp/out" 2>&1; }
check || { cat "$tmp/out"; exit 1; }
[[ "$(grep -c '^  OK ' "$tmp/out")" = 4 ]]
[[ "$(grep -c '^  BRANCH ' "$tmp/out")" = 1 ]]
grep -q 'checked 5 pins' "$tmp/out"
grep -q 'repos/github/codeql-action/git/tags/dddd' "$PIN_API_LOG"
[[ "$(grep -c 'repos/actions/checkout/git/ref/tags/v1.2.3' "$PIN_API_LOG")" = 1 ]]
! grep -q 'rust-toolchain' "$PIN_API_LOG"
cp "$workflow" "$tmp/good"
expect_failure() {
    if check; then echo 'checker unexpectedly passed'; cat "$tmp/out"; exit 1; fi
    grep -q "$1" "$tmp/out" || { cat "$tmp/out"; exit 1; }
}
sed 's/# v1.2.3/# v9.9.9/g' "$tmp/good" > "$workflow"
expect_failure 'FAIL.*actions/checkout.*pinned'
cp "$tmp/good" "$workflow"
check || { cat "$tmp/out"; exit 1; }
sed 's/# v1.2.3/# v0.0.0/g' "$tmp/good" > "$workflow"
expect_failure 'ERROR.*actions/checkout.*cannot resolve'
sed 's/# stable (branch)/# stable/' "$tmp/good" > "$workflow"
expect_failure 'ERROR.*rust-toolchain'
sed 's/# v1.2.3//g' "$tmp/good" > "$workflow"
expect_failure 'missing version comment'
sed 's#uses: ./.github/actions/local#uses: ./local-action#' "$tmp/good" > "$workflow"
expect_failure 'local action outside .github/actions'
printf 'jobs: {test: {uses: "actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}} # v1.2.3' > "$workflow"
check || { cat "$tmp/out"; exit 1; }
grep -q 'checked 1 pins' "$tmp/out"
printf 'jobs: {}\n' > "$workflow"
expect_failure 'no pinned actions'
printf 'jobs: [\n' > "$workflow"
expect_failure 'cannot read workflow'
rm "$workflow"
expect_failure 'no workflow files'
mkdir "$workflow"
expect_failure 'cannot read workflow'
rmdir "$workflow"
cp "$tmp/good" "$workflow"
# A valid workflow must not hide another input that cannot be opened.
mkdir "$tmp/repo/.github/workflows/unreadable.yml"
expect_failure 'cannot read workflow'
echo 'action pin comment fixtures passed'
