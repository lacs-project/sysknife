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
| RUSTSEC-2026-0097 | `rand` 0.7.3 | Unsound with a custom logger. Pulled via `phf` → `selectors` → `kuchikiki` → `tauri-utils`. **Explicitly `--ignore`d** in CI (it is a non-`unmaintained` class that would otherwise fail the build). |
| RUSTSEC-2024-0429 | `glib` | Unsoundness in `VariantStrIter` iterator impls. GTK3 binding stack. |

## Unmaintained

| Advisory | Crate | Note |
|---|---|---|
| RUSTSEC-2024-0411 | `gdkwayland-sys` | gtk-rs GTK3 bindings — unmaintained |
| RUSTSEC-2024-0412 | `gdk` | gtk-rs GTK3 bindings — unmaintained |
| RUSTSEC-2024-0413 | `atk` | gtk-rs GTK3 bindings — unmaintained |
| RUSTSEC-2024-0414 | `gdkx11-sys` | gtk-rs GTK3 bindings — unmaintained |
| RUSTSEC-2024-0415 | `gtk` | gtk-rs GTK3 bindings — unmaintained |
| RUSTSEC-2024-0416 | `atk-sys` | gtk-rs GTK3 bindings — unmaintained |
| RUSTSEC-2024-0417 | `gdkx11` | gtk-rs GTK3 bindings — unmaintained |
| RUSTSEC-2024-0418 | `gdk-sys` | gtk-rs GTK3 bindings — unmaintained |
| RUSTSEC-2024-0419 | `gtk3-macros` | gtk-rs GTK3 bindings — unmaintained |
| RUSTSEC-2024-0420 | `gtk-sys` | gtk-rs GTK3 bindings — unmaintained |
| RUSTSEC-2024-0384 | `instant` | unmaintained (transitive via GUI/webview) |
| RUSTSEC-2024-0370 | `proc-macro-error` | unmaintained (transitive) |
| RUSTSEC-2025-0012 | `backoff` | unmaintained (transitive) |
| RUSTSEC-2025-0057 | `fxhash` | unmaintained (transitive) |
| RUSTSEC-2025-0075 | `unic-char-range` | unmaintained (transitive) |
| RUSTSEC-2025-0080 | `unic-common` | unmaintained (transitive) |
| RUSTSEC-2025-0081 | `unic-char-property` | unmaintained (transitive) |
| RUSTSEC-2025-0098 | `unic-ucd-version` | unmaintained (transitive) |
| RUSTSEC-2025-0100 | `unic-ucd-ident` | unmaintained (transitive) |

## Policy

- **Vulnerabilities** (RUSTSEC advisories of type `vulnerability`) are never
  accepted here — they fail CI and must be fixed or the dependency dropped.
- **Unmaintained** advisories are reported as non-fatal warnings by default;
  they are left visible (not globally ignored) so the team notices if the set
  grows. This file is the record of the currently-accepted set and why.
- Re-evaluate the GTK3 entries when Tauri migrates its Linux backend off the
  GTK3 binding stack; re-evaluate `rand` when the webview dep chain bumps it.
