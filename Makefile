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
	# Every helper the daemon calls must be here; `cargo nextest run -p
	# sysknife-daemon --test helper_install_coverage` derives the required set
	# from the daemon source and fails if one is missing.
	install -Dm 755 packaging/sysknife-apt-pin-edit $(HELPERS)/apt-pin-edit
	install -Dm 755 packaging/sysknife-audit-edit $(HELPERS)/audit-edit
	install -Dm 755 packaging/sysknife-fail2ban-jail-edit $(HELPERS)/fail2ban-jail-edit
	install -Dm 755 packaging/sysknife-grub-kargs-edit $(HELPERS)/grub-kargs-edit
	install -Dm 755 packaging/sysknife-log-edit $(HELPERS)/log-edit
	install -Dm 755 packaging/sysknife-mount-edit $(HELPERS)/mount-edit
	install -Dm 755 packaging/sysknife-pam-edit $(HELPERS)/pam-edit
	install -Dm 755 packaging/sysknife-scheduled-job-edit $(HELPERS)/scheduled-job-edit
	install -Dm 755 packaging/sysknife-sshd-option-edit $(HELPERS)/sshd-option-edit
	install -Dm 755 packaging/sysknife-sudoers-edit $(HELPERS)/sudoers-edit
	install -Dm 755 packaging/sysknife-sysctl-edit $(HELPERS)/sysctl-edit
	install -Dm 755 packaging/sysknife-unattended-upgrades-edit $(HELPERS)/unattended-upgrades-edit

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
	rm -f $(HELPERS)/apt-pin-edit
	rm -f $(HELPERS)/audit-edit
	rm -f $(HELPERS)/fail2ban-jail-edit
	rm -f $(HELPERS)/grub-kargs-edit
	rm -f $(HELPERS)/log-edit
	rm -f $(HELPERS)/mount-edit
	rm -f $(HELPERS)/pam-edit
	rm -f $(HELPERS)/scheduled-job-edit
	rm -f $(HELPERS)/sshd-option-edit
	rm -f $(HELPERS)/sudoers-edit
	rm -f $(HELPERS)/sysctl-edit
	rm -f $(HELPERS)/unattended-upgrades-edit
	@echo "Daemon uninstalled. User 'sysknife' and /var/lib/sysknife data were NOT removed."
	@echo "To remove them manually: userdel sysknife && rm -rf /var/lib/sysknife /run/sysknife"

## ── Dev checks ───────────────────────────────────────────────────────────────

check:
	cargo nextest run --workspace --locked
	cargo clippy --workspace --locked -- -D warnings
