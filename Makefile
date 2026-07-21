# SysKnife Makefile — build, install, and uninstall the daemon and CLI.
#
# Typical usage (as root or via sudo):
#   make build
#   sudo make install
#   sudo make uninstall
#
# PREFIX can be overridden: sudo make install PREFIX=/opt/sysknife

PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin

# Default system paths. Override on rpm-ostree systems (Silverblue,
# Kinoite, Sericea, Onyx) where /usr is read-only — use /etc instead:
#
#   sudo make install \
#       SYSUSERS=/etc/sysusers.d \
#       TMPFILES=/etc/tmpfiles.d \
#       SYSTEMD=/etc/systemd/system \
#       POLKIT=/etc/polkit-1/rules.d
#
SYSUSERS    ?= /usr/lib/sysusers.d
TMPFILES    ?= /usr/lib/tmpfiles.d
SYSTEMD     ?= /usr/lib/systemd/system
POLKIT      ?= /usr/share/polkit-1/rules.d
SUDOERS     ?= /etc/sudoers.d
HELPERS     ?= /usr/lib/sysknife

CARGO_BUILD_FLAGS ?= --release --locked

.PHONY: build install uninstall daemon-install cli-install daemon-uninstall cli-uninstall check

## ── Build ────────────────────────────────────────────────────────────────────

# Builds both binaries: the privileged daemon (sysknife-daemon) and the user CLI
# (sysknife), which provides `mcp-server` and `approve`. Docs run `sysknife` right
# after `make install`, so `install` must place both — see cli-install below.
build:
	cargo build $(CARGO_BUILD_FLAGS) -p sysknife-daemon -p sysknife-cli
	@echo "Build complete. Binaries: target/release/sysknife-daemon, target/release/sysknife"

## ── Install ──────────────────────────────────────────────────────────────────

install: daemon-install cli-install
	@echo ""
	@echo "SysKnife daemon + CLI installed. Run 'sudo systemctl enable --now sysknife-daemon' to start."

# The `sysknife` CLI is what the setup wizard (`--no-binary`) and the MCP server
# invoke, so a from-source install must place it on PATH alongside the daemon.
cli-install: build
	install -Dm 755 target/release/sysknife $(BINDIR)/sysknife
	@echo "CLI installed: $(BINDIR)/sysknife"

daemon-install: build
	install -Dm 755 target/release/sysknife-daemon $(BINDIR)/sysknife-daemon

	# System user and group (idempotent via systemd-sysusers).
	install -Dm 644 packaging/sysknife-sysusers.conf $(SYSUSERS)/sysknife.conf
	systemd-sysusers $(SYSUSERS)/sysknife.conf

	# Runtime and state directories (idempotent via systemd-tmpfiles).
	install -Dm 644 packaging/sysknife-tmpfiles.conf $(TMPFILES)/sysknife.conf
	systemd-tmpfiles --create $(TMPFILES)/sysknife.conf

	# systemd unit.
	install -Dm 644 packaging/sysknife-daemon.service $(SYSTEMD)/sysknife-daemon.service
	systemctl daemon-reload

	# polkit rules.
	install -Dm 644 packaging/50-sysknife.rules $(POLKIT)/50-sysknife.rules

	# sudoers fragment (visudo validates before install).
	visudo -cf packaging/sysknife-sudoers
	install -Dm 440 packaging/sysknife-sudoers $(SUDOERS)/sysknife

	# Privileged helper scripts — root-owned, not writable by sysknife.
	install -Dm 755 packaging/sysknife-grub-kargs-edit $(HELPERS)/grub-kargs-edit

## ── Uninstall ────────────────────────────────────────────────────────────────

uninstall: daemon-uninstall cli-uninstall

cli-uninstall:
	rm -f $(BINDIR)/sysknife
	@echo "CLI uninstalled: $(BINDIR)/sysknife"

daemon-uninstall:
	-systemctl disable --now sysknife-daemon 2>/dev/null || true
	rm -f $(BINDIR)/sysknife-daemon
	rm -f $(SYSTEMD)/sysknife-daemon.service
	systemctl daemon-reload
	rm -f $(POLKIT)/50-sysknife.rules
	rm -f $(SUDOERS)/sysknife
	rm -f $(SYSUSERS)/sysknife.conf
	rm -f $(TMPFILES)/sysknife.conf
	rm -f $(HELPERS)/grub-kargs-edit
	@echo "Daemon uninstalled. User 'sysknife' and /var/lib/sysknife data were NOT removed."
	@echo "To remove them manually: userdel sysknife && rm -rf /var/lib/sysknife /run/sysknife"

## ── Dev checks ───────────────────────────────────────────────────────────────

check:
	cargo nextest run --workspace --locked
	cargo clippy --workspace --locked -- -D warnings
