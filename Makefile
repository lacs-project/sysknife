# SysKnife Makefile — build, install, and uninstall the daemon and CLI.
#
# Typical usage (as root or via sudo):
#   make build
#   sudo make install
#   sudo make uninstall
#
# PREFIX can be overridden: sudo make install PREFIX=/opt/sysknife
#
# DESTDIR stages the install for packaging: every file lands under it, and the
# steps that activate an install on this host (systemd-sysusers,
# systemd-tmpfiles, systemctl) are skipped for the package to run later:
#   make install DESTDIR=/tmp/stage

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

# Every directory daemon-install writes into, in one place so the preflight
# below cannot fall behind the recipe. tests/release/install-paths.test.sh
# derives the recipe's own $(VAR) uses and fails if this list disagrees.
INSTALL_DIRS = $(BINDIR) $(SYSUSERS) $(TMPFILES) $(SYSTEMD) $(POLKIT) \
               $(SUDOERS) $(HELPERS)

CARGO_BUILD_FLAGS ?= --release --locked

# Run a command that acts on the running host, or name it and skip it when
# DESTDIR stages the install somewhere else.
on_host = $(if $(DESTDIR),@echo "DESTDIR set; skipped: $(1)",$(1))

.PHONY: build install uninstall daemon-install daemon-install-preflight \
	cli-install daemon-uninstall cli-uninstall check

## ── Build ────────────────────────────────────────────────────────────────────

# Builds both binaries: the privileged daemon (sysknife-daemon) and the user CLI
# (sysknife), which provides `mcp-server` and `approve`. Docs run `sysknife` right
# after `make install`, so `install` must place both — see cli-install below.
build:
	cargo build $(CARGO_BUILD_FLAGS) -p sysknife-daemon -p sysknife-cli
	@echo "Build complete. Binaries: target/release/sysknife-daemon, target/release/sysknife"

## ── Preflight ────────────────────────────────────────────────────────────────

# Refuse an install that cannot finish, before it writes anything.
#
# daemon-install is a sequence of `install` calls with no rollback, so a
# directory that turns out to be unwritable halfway leaves a working systemd
# unit and twelve sudo grants naming helper scripts that were never installed.
# That is worse than not installing at all: the grants are live and their
# targets are absent. Observed on Fedora Atomic, where /usr is read-only and
# $(HELPERS) defaults underneath it (see issue #301).
#
# `install -D` creates missing parents, so the thing to test is the nearest
# ancestor that exists, not the leaf.
daemon-install-preflight:
	@unwritable=""; \
	for d in $(INSTALL_DIRS); do \
		probe="$(DESTDIR)$$d"; \
		while [ ! -d "$$probe" ] && [ "$$probe" != "/" ]; do \
			probe="$$(dirname "$$probe")"; \
		done; \
		[ -w "$$probe" ] || unwritable="$$unwritable $$d"; \
	done; \
	if [ -n "$$unwritable" ]; then \
		echo "make: refusing to install; nothing has been written." >&2; \
		echo "" >&2; \
		echo "These directories are not writable:" >&2; \
		for d in $$unwritable; do echo "  $$d" >&2; done; \
		echo "" >&2; \
		echo "On an rpm-ostree host (Silverblue, Kinoite, Sericea, Onyx)" >&2; \
		echo "/usr is read-only. See docs/distro-support.md and issue #301." >&2; \
		exit 1; \
	fi

## ── Install ──────────────────────────────────────────────────────────────────

install: daemon-install cli-install
	@echo ""
	@echo "SysKnife daemon + CLI installed. Run 'sudo systemctl enable --now sysknife-daemon' to start."

# The `sysknife` CLI is what the setup wizard (`--no-binary`) and the MCP server
# invoke, so a from-source install must place it on PATH alongside the daemon.
cli-install: build
	install -Dm 755 target/release/sysknife $(DESTDIR)$(BINDIR)/sysknife
	@echo "CLI installed: $(DESTDIR)$(BINDIR)/sysknife"

daemon-install: daemon-install-preflight build
	install -Dm 755 target/release/sysknife-daemon $(DESTDIR)$(BINDIR)/sysknife-daemon

	# System user and group (idempotent via systemd-sysusers).
	install -Dm 644 packaging/sysknife-sysusers.conf $(DESTDIR)$(SYSUSERS)/sysknife.conf
	$(call on_host,systemd-sysusers $(SYSUSERS)/sysknife.conf)

	# Runtime and state directories (idempotent via systemd-tmpfiles).
	install -Dm 644 packaging/sysknife-tmpfiles.conf $(DESTDIR)$(TMPFILES)/sysknife.conf
	$(call on_host,systemd-tmpfiles --create $(TMPFILES)/sysknife.conf)

	# systemd unit.
	install -Dm 644 packaging/sysknife-daemon.service $(DESTDIR)$(SYSTEMD)/sysknife-daemon.service
	$(call on_host,systemctl daemon-reload)

	# polkit rules.
	install -Dm 644 packaging/50-sysknife.rules $(DESTDIR)$(POLKIT)/50-sysknife.rules

	# Privileged helper scripts — root-owned, not writable by sysknife.
	# Every helper the daemon calls must be here; `cargo nextest run -p
	# sysknife-daemon --test helper_install_coverage` derives the required set
	# from the daemon source and fails if one is missing.
	install -Dm 755 packaging/sysknife-apt-pin-edit $(DESTDIR)$(HELPERS)/apt-pin-edit
	install -Dm 755 packaging/sysknife-action-steps $(DESTDIR)$(HELPERS)/action-steps
	install -Dm 755 packaging/sysknife-firewall-state $(DESTDIR)$(HELPERS)/firewall-state
	install -Dm 755 packaging/sysknife-audit-edit $(DESTDIR)$(HELPERS)/audit-edit
	install -Dm 755 packaging/sysknife-fail2ban-jail-edit $(DESTDIR)$(HELPERS)/fail2ban-jail-edit
	install -Dm 755 packaging/sysknife-fail2ban-ban $(DESTDIR)$(HELPERS)/fail2ban-ban
	install -Dm 755 packaging/sysknife-grub-kargs-edit $(DESTDIR)$(HELPERS)/grub-kargs-edit
	install -Dm 755 packaging/sysknife-log-edit $(DESTDIR)$(HELPERS)/log-edit
	install -Dm 755 packaging/sysknife-mount-edit $(DESTDIR)$(HELPERS)/mount-edit
	install -Dm 755 packaging/sysknife-pam-edit $(DESTDIR)$(HELPERS)/pam-edit
	install -Dm 755 packaging/sysknife-scheduled-job-edit $(DESTDIR)$(HELPERS)/scheduled-job-edit
	install -Dm 755 packaging/sysknife-sshd-option-edit $(DESTDIR)$(HELPERS)/sshd-option-edit
	install -Dm 755 packaging/sysknife-sudoers-edit $(DESTDIR)$(HELPERS)/sudoers-edit
	install -Dm 755 packaging/sysknife-sysctl-edit $(DESTDIR)$(HELPERS)/sysctl-edit
	install -Dm 755 packaging/sysknife-unattended-upgrades-edit $(DESTDIR)$(HELPERS)/unattended-upgrades-edit

	# Install grants last: a failed helper install must not activate new grants
	# pointing at absent or stale helpers. Validate the fragment before install.
	visudo -cf packaging/sysknife-sudoers
	install -Dm 440 packaging/sysknife-sudoers $(DESTDIR)$(SUDOERS)/sysknife

## ── Uninstall ────────────────────────────────────────────────────────────────

uninstall: daemon-uninstall cli-uninstall

cli-uninstall:
	rm -f $(DESTDIR)$(BINDIR)/sysknife
	@echo "CLI uninstalled: $(DESTDIR)$(BINDIR)/sysknife"

daemon-uninstall:
	$(if $(DESTDIR),,-systemctl disable --now sysknife-daemon 2>/dev/null || true)
	rm -f $(DESTDIR)$(BINDIR)/sysknife-daemon
	rm -f $(DESTDIR)$(SYSTEMD)/sysknife-daemon.service
	$(call on_host,systemctl daemon-reload)
	rm -f $(DESTDIR)$(POLKIT)/50-sysknife.rules
	rm -f $(DESTDIR)$(SUDOERS)/sysknife
	rm -f $(DESTDIR)$(SYSUSERS)/sysknife.conf
	rm -f $(DESTDIR)$(TMPFILES)/sysknife.conf
	rm -f $(DESTDIR)$(HELPERS)/apt-pin-edit
	rm -f $(DESTDIR)$(HELPERS)/action-steps
	rm -f $(DESTDIR)$(HELPERS)/firewall-state
	rm -f $(DESTDIR)$(HELPERS)/audit-edit
	rm -f $(DESTDIR)$(HELPERS)/fail2ban-jail-edit
	rm -f $(DESTDIR)$(HELPERS)/fail2ban-ban
	rm -f $(DESTDIR)$(HELPERS)/grub-kargs-edit
	rm -f $(DESTDIR)$(HELPERS)/log-edit
	rm -f $(DESTDIR)$(HELPERS)/mount-edit
	rm -f $(DESTDIR)$(HELPERS)/pam-edit
	rm -f $(DESTDIR)$(HELPERS)/scheduled-job-edit
	rm -f $(DESTDIR)$(HELPERS)/sshd-option-edit
	rm -f $(DESTDIR)$(HELPERS)/sudoers-edit
	rm -f $(DESTDIR)$(HELPERS)/sysctl-edit
	rm -f $(DESTDIR)$(HELPERS)/unattended-upgrades-edit
	@echo "Daemon uninstalled. User 'sysknife' and /var/lib/sysknife data were NOT removed."
	@echo "To remove them manually: userdel sysknife && rm -rf /var/lib/sysknife /run/sysknife"

## ── Dev checks ───────────────────────────────────────────────────────────────

check:
	bash scripts/ci-local.sh --fast
