# SysKnife Shell — Flatpak Packaging

## Prerequisites

```bash
flatpak install flathub org.gnome.Platform//47 org.gnome.Sdk//47
flatpak install flathub org.freedesktop.Sdk.Extension.rust-stable
pip install flatpak-cargo-generator
```

## Generate Cargo sources

Flatpak builds without network access, so all Rust crates must be
vendored. Generate the offline vendor manifest from the workspace lock file:

```bash
cd packaging/flatpak
python3 flatpak-cargo-generator.py ../../Cargo.lock -o cargo-sources.json
```

The generated `cargo-sources.json` tells the build where to download each
crate beforehand. Commit this file whenever `Cargo.lock` changes.

## Build and install

```bash
flatpak-builder --force-clean --install --user \
  _build packaging/flatpak/org.lacsfoundation.LacsShell.json
```

## Run

```bash
flatpak run org.lacsfoundation.LacsShell
```

## Notes

- The Flatpak shell connects to the daemon at `/run/sysknife/daemon.sock` on
  the **host** (not sandboxed) via `--filesystem=/run/sysknife:ro`.
- The daemon must still be installed and running on the host via the
  systemd unit (`sudo systemctl enable --now sysknife-daemon`).
- `cargo-sources.json` must be regenerated with `flatpak-cargo-generator.py`
  whenever `Cargo.lock` changes. Add this to your release checklist.
