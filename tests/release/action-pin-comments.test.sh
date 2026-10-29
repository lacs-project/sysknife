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
# A tag-ref lookup answers with the ref GitHub resolved, then the object. The
# ref is printed only when the caller's --jq asks for it, as the real API does.
ref_answer() { if [[ "${*:4}" == *'.ref '* ]]; then echo "$1 $2 $3"; else echo "$2 $3"; fi; }
case "$2" in
  repos/actions/checkout/git/ref/tags/v1.2.3) ref_answer refs/tags/v1.2.3 commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$@" ;;
  repos/actions/checkout/git/ref/tags/v9.9.9) ref_answer refs/tags/v9.9.9 commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "$@" ;;
  # GHSA-j754: GitHub normalises `..` in the path, so this "tag" lookup returns a
  # pull-request head that anyone can push to.
  repos/actions/checkout/git/ref/tags/v1.2.3/../../pull/1/head) ref_answer refs/pull/1/head commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$@" ;;
  repos/github/codeql-action/git/ref/tags/v4.37.9) ref_answer refs/tags/v4.37.9 tag cccccccccccccccccccccccccccccccccccccccc "$@" ;;
  repos/github/codeql-action/git/tags/cccccccccccccccccccccccccccccccccccccccc) echo 'tag dddddddddddddddddddddddddddddddddddddddd' ;;
  repos/github/codeql-action/git/tags/dddddddddddddddddddddddddddddddddddddddd) echo 'commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ;;
  repos/dtolnay/rust-toolchain/compare/stable...aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
    if [[ "${PIN_BRANCH_ERROR:-0}" = 1 ]]; then
      echo 'HTTP 404 or API unavailable (branch fixture)' >&2; exit 1
    fi
    printf '%s\n' "${PIN_BRANCH_STATUS-behind}" ;;
  # These forbidden markers would pass reachability if the allowlist vanished.
  repos/actions/checkout/compare/main...aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|\
  repos/dtolnay/rust-toolchain/compare/nightly...aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|\
  repos/dtolnay/rust-toolchain/subpath/compare/stable...aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
    echo behind ;;
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
cp "$workflow" "$tmp/good"
expect_failure() {
    if check; then echo 'checker unexpectedly passed'; cat "$tmp/out"; exit 1; fi
    grep -q "$1" "$tmp/out" || { cat "$tmp/out"; exit 1; }
}
# A version comment must name a tag: one that GitHub resolves to any other ref
# (here a pull-request head, through `..` in the path) is refused (GHSA-j754).
sed 's|# v1.2.3$|# v1.2.3/../../pull/1/head|' "$tmp/good" > "$workflow"
grep -q 'pull/1/head' "$workflow" || { echo 'fixture edit did not apply'; exit 1; }
expect_failure 'ERROR.*actions/checkout.*cannot resolve tag v1.2.3/../../pull/1/head'
# A branch marker is not an escape from verifying arbitrary action SHAs.
sed 's/# v1.2.3/# main (branch)/g' "$tmp/good" > "$workflow"
expect_failure 'actions/checkout.*not allowed'
sed 's/# stable (branch)/# nightly (branch)/' "$tmp/good" > "$workflow"
expect_failure 'rust-toolchain.*not allowed'
sed 's#dtolnay/rust-toolchain@#dtolnay/rust-toolchain/subpath@#' "$tmp/good" > "$workflow"
expect_failure 'rust-toolchain/subpath.*not allowed'
cp "$tmp/good" "$workflow"
check || { cat "$tmp/out"; exit 1; }
grep -q 'repos/dtolnay/rust-toolchain/compare/stable...aaaa' "$PIN_API_LOG"
export PIN_BRANCH_STATUS=identical
check || { cat "$tmp/out"; exit 1; }
for PIN_BRANCH_STATUS in ahead diverged unexpected ''; do
    export PIN_BRANCH_STATUS
    expect_failure 'rust-toolchain.*not reachable'
done
export PIN_BRANCH_STATUS=behind PIN_BRANCH_ERROR=1
expect_failure 'rust-toolchain.*cannot verify'
unset PIN_BRANCH_ERROR PIN_BRANCH_STATUS

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
