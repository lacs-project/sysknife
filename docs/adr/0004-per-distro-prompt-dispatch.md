# ADR 0004: Per-distro Prompt Dispatch

## Status

Accepted (merged in PR #203, 2026-04-25).

## Context

SysKnife gained Ubuntu/Debian action support in Phase 2b. The action catalogue
split into two mostly non-overlapping sets:

- **Fedora-family**: `AddLayeredPackage`, `RemoveLayeredPackage`,
  `rpm-ostree` deployment controls, `flatpak`, `toolbox`, `firewalld`, …
- **Debian-family**: `AptInstall`, `AptRemove`, `AptUpdate`, `snap`,
  `distrobox`, `ufw`, `netplan`, …

The original single-distro prompt listed all action names in one block.
After adding Debian actions this caused two problems:

1. **Prompt confusion**: the model saw both `AddLayeredPackage` and `AptInstall`
   for every intent and had to infer which to use from context. In practice,
   GPT-4o and Claude sometimes proposed the wrong family — `AptInstall` on
   Silverblue, or `AddLayeredPackage` on Ubuntu — especially for compound
   intents that did not name the package manager explicitly.

2. **Context window waste**: every planning call carried ~40% action names that
   could never legally be executed on the current host.

The E2E story suite (65/65 passing on Ubuntu 24.04 with gpt-4.1) validated
that per-distro isolation fixes (1) and reduces prompt size meaningfully.

## Decision

`build_system_prompt` dispatches to one of three **pure render functions**
based on `distro_hint.family`:

```text
distro_hint.family == "fedora"  →  render_fedora_prompt
distro_hint.family == "debian"  →  render_debian_prompt
_                               →  render_generic_prompt
```

Each render function concatenates:

1. Shared `const` blocks: role, the single-planning-rule, cross-distro action
   catalogue, and the six worked examples (A–F).
2. Per-distro `const` blocks: distro header (with detected version),
   distro-specific action catalogue, risk overrides, selection rules, and
   action parameter reference.

The `FEDORA_ONLY_ACTIONS` and `DEBIAN_ONLY_ACTIONS` string-slice constants
back safety-fence unit tests that assert no cross-contamination at the type
level.

The `DistroHint` is provided by `sysknife-core`'s `detect_distro()` function
which reads `/etc/os-release` at startup. If detection fails, `distro_hint` is
`None` and `render_generic_prompt` is used.

## Consequences

- The model cannot propose a Fedora-specific action on a Debian host (or vice
  versa) because the action name simply does not appear in its context window.
- Adding a new distro family requires: a new `render_*` function, a new
  `DISTRO_FAMILY_*` constant, a dispatch arm in `build_system_prompt`, and a
  `*_ONLY_ACTIONS` slice for the safety fence. This is intentionally mechanical
  — each step has a test to confirm it.
- Prompt size decreases by roughly 20–25% for Fedora hosts and 15–20% for
  Debian hosts compared to the pre-dispatch single-prompt.
- The generic fallback deliberately omits all distro-specific actions. A host
  with an unrecognised `/etc/os-release` gets cross-distro-only planning until
  the user adds a manual `distro_hint` override in
  `~/.config/sysknife/config.toml`.

## References

- PR #203 — "refactor(prompt): per-distro dispatch"
- `crates/sysknife-brain/src/prompt.rs` — implementation
- `docs/architecture.md` — prompt construction overview
- `docs/research/prompt-composition-patterns.md` — survey of dynamic
  prompt patterns that informed this design (dynamic middleware, template
  composition, conditional blocks)
