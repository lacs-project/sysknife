#!/usr/bin/env bash
#
# database-path-agreement.test.sh — the installer and the daemon must open the
# same SQLite audit database.
#
# They did not. `install-daemon.js` pinned `~/.local/share/sysknife/daemon.sqlite`
# into the systemd unit while `sysknife_core::default_database_path()` resolved
# `$XDG_STATE_HOME/sysknife/daemon.sqlite`, falling back to
# `~/.local/state/sysknife/daemon.sqlite`. The daemon therefore opened one
# database when systemd started it and a different one when started any other
# way — including the way the installer's own "Next steps" suggests. Two audit
# chains, and `sysknife audit verify` only ever sees the one belonging to the
# daemon it is talking to, so neither reports anything wrong.
#
# The drift survived a commit titled "doc-drift sweep", which pinned the
# installer's value in a unit test instead of reconciling it against the binary
# and the two docs pages that documented the state path. A test that pins one
# side of a disagreement makes the disagreement permanent, which is why this
# guard compares the two sides against each other rather than against a literal.
#
# Host-side only: no VM, no daemon, no network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
installer="$repo_root/packages/setup/install-daemon.js"
core_rs="$repo_root/crates/sysknife-core/src/lib.rs"

[ -f "$installer" ] || { printf 'missing %s\n' "$installer" >&2; exit 1; }
[ -f "$core_rs" ]    || { printf 'missing %s\n' "$core_rs" >&2; exit 1; }

# The installer's answer, asked the way the installer asks it. A fixed HOME with
# XDG_STATE_HOME unset exercises the fallback branch, which is the one a normal
# Ubuntu desktop or server session takes.
js_path="$(HOME=/home/testuser node -e "
  delete process.env.XDG_STATE_HOME;
  process.env.HOME = '/home/testuser';
  const os = require('node:os');
  os.homedir = () => '/home/testuser';
  console.log(require('$installer').databasePath());
")"

# The daemon's answer, read out of the source rather than executed, so this stays
# a fast host-side check that needs no build.
rs_suffix="$(grep -oE '"\.local/state/sysknife/daemon\.sqlite"|"\.local/share/sysknife/daemon\.sqlite"' "$core_rs" | head -1 | tr -d '"' || true)"
if [ -z "$rs_suffix" ]; then
    printf 'FAIL: could not find the fallback database path in %s.\n' "$core_rs" >&2
    printf '      default_database_path() changed shape; update this guard rather than deleting it.\n' >&2
    exit 1
fi
rs_path="/home/testuser/$rs_suffix"

if [ "$js_path" != "$rs_path" ]; then
    printf 'FAIL: the installer and the daemon disagree about the audit database.\n' >&2
    printf '  installer (install-daemon.js): %s\n' "$js_path" >&2
    printf '  daemon    (default_database_path): %s\n' "$rs_path" >&2
    printf '\nA daemon started by the unit would write one audit chain and a daemon\n' >&2
    printf 'started by hand another. Make both sides name the same path.\n' >&2
    exit 1
fi

# The docs are the third opinion, and were right when the code was not.
for doc in docs/configuration.md docs/developer-guide.md; do
    if ! grep -q "$rs_suffix" "$repo_root/$doc"; then
        printf 'FAIL: %s no longer documents %s\n' "$doc" "$rs_suffix" >&2
        exit 1
    fi
done

printf 'Installer, daemon and docs agree on %s.\n' "$js_path"
