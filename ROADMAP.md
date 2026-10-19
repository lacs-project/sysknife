# Roadmap

This roadmap is intentionally high level. It is meant to show
contributors where the project is going and what matters next.

It lists **open work only**. Shipped work is not repeated here: see
[CHANGELOG.md](CHANGELOG.md) for what landed in each release, and the
[GitHub releases](https://github.com/lacs-project/sysknife/releases) for the
artefacts.

## Phase 8: Multi-distro

Tracked in the v0.4.0 milestone. Ubuntu is the primary target today (20.04 and
later) because that is where the users are; Fedora Atomic 41+ is eligible and its
rpm-ostree action families work, but `make install` cannot finish on a read-only
`/usr` yet ([#301](https://github.com/lacs-project/sysknife/issues/301)). See
[docs/distro-support.md](docs/distro-support.md).

- install on rpm-ostree hosts (#301), then record a current Fedora Silverblue
  44 full VM run
- dnf action family (Fedora Workstation non-atomic)
- pacman action family (Arch/Manjaro)

## Phase 9: Launch

- record a demo video on real hardware with rollback visible (#32)
- Telegram interface (`sysknife-bot`) — approve plans from your phone via
  inline buttons; the viral mechanic

## Phase 10: Ecosystem

- web dashboard for teams and fleet management
