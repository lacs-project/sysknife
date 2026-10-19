# Accepted `cargo audit` advisories

`cargo audit` is run in CI (`.github/workflows/ci.yml`, `security-audit` job).
It **fails the build on any vulnerability**. The advisories listed here are the
accepted **unmaintained** and **unsound** warnings — every one of them enters
the dependency graph **only** through the Tauri desktop shell
(`sysknife-shell`) and its GTK3 / webview stack.

**None of these crates are reachable from the release-published crates** —
`sysknife-proto`, `sysknife-core`, `sysknife-types`, `sysknife-brain`,
`sysknife-daemon`, or `sysknife-cli`. The privileged daemon and the CLI (the
security-sensitive trust boundary) do not link any of them. Verify with:

```sh
cargo tree -e no-dev -i <crate>        # shows the path is via tauri/gtk only
cargo audit                             # full current report
```

## Unsound (informational)

| Advisory | Crate | Note |
|---|---|---|
| RUSTSEC-2024-0429 | `glib` | Unsoundness in `VariantStrIter` iterator impls. GTK3 binding stack. |

`RUSTSEC-2026-0097` (`rand` 0.7.3, reached via `phf` → `selectors` → `kuchikiki`
→ `tauri-utils`) used to be listed here and `--ignore`d in CI. The crate has
since left the lockfile — only `rand` 0.9.4 and 0.10.2 are built — so
`cargo audit` now runs with no ignore at all. The ignore was removed rather than
left in place: an ignore for a crate that is not built protects nothing, and
would silently re-accept the advisory if a future dependency bump pulled 0.7.3
back in.

## Unmaintained

| Advisory | Crate | Note |
|---|---|---|
| RUSTSEC-2024-0370 | `proc-macro-error` | unmaintained (transitive, Tauri build stack) |

## Removed from this record

- **The gtk-rs GTK3 bindings** (RUSTSEC-2024-0411 to RUSTSEC-2024-0420:
  `gdkwayland-sys`, `gdk`, `atk`, `gdkx11-sys`, `gtk`, `atk-sys`, `gdkx11`,
  `gdk-sys`, `gtk3-macros`, `gtk-sys`). RustSec withdrew these advisories on
  2026-08-14, so `cargo audit` no longer reports them, although the crates are
  still built for the shell.
- **`instant`, `backoff`, `fxhash` and the five `unic-*` crates**
  (RUSTSEC-2024-0384, RUSTSEC-2025-0012, RUSTSEC-2025-0057, RUSTSEC-2025-0075,
  RUSTSEC-2025-0080, RUSTSEC-2025-0081, RUSTSEC-2025-0098, RUSTSEC-2025-0100).
  None of them is in `Cargo.lock` any more.
- **`event-listener` 5.4.1** (RUSTSEC-2026-0221, unsound: a `!Send` tag set
  with `Event::with_tag` could cross threads through `StackSlot`). Unlike every
  other entry here it reached the daemon and the CLI, through `sqlx-core`. It
  was never accepted: the lockfile moved to 5.4.2, which carries the fix, on
  2026-10-13.

## Policy

- **Vulnerabilities** (RUSTSEC advisories of type `vulnerability`) are never
  accepted here — they fail CI and must be fixed or the dependency dropped.
- **Unmaintained** advisories are reported as non-fatal warnings by default;
  they are left visible (not globally ignored) so the team notices if the set
  grows. This file is the record of the currently-accepted set and why.
- An unsound or unmaintained advisory on a crate the daemon, CLI or brain links
  is not accepted here; bump it or drop the dependency. Check reach with
  `cargo tree -e no-dev -i <crate>` before adding a row.
- Re-evaluate `glib` when Tauri migrates its Linux backend off the GTK3 binding
  stack.
