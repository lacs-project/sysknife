# Firewall observations

Use `GetFirewallBackendState` for a general firewall-state question. It probes
nftables JSON, `ufw status verbose`, and `firewall-cmd --list-all`. It reports
observed frontends and hooked nftables rules, preserving the individual probe
output and failure status. `query_firewall` uses this action during planning.

`GetNftablesRuleset` runs the fixed read-only `sudo nft list ruleset` command.
The sudoers grants allow only that command and its JSON form; neither grant
allows changing the ruleset. The reporter helper itself runs without sudo.

An inactive ufw frontend does not imply the machine has no firewall. Likewise,
an empty nftables ruleset or a failed probe is not proof that traffic is
unfiltered: legacy iptables, other namespaces and other mechanisms can exist.
The reporter returns `unknown` when it cannot identify an observed backend.
Even observed rules do not establish whether particular traffic is blocked.

Frontends may coexist or use nftables underneath, so the output is a list of
observations rather than a mutually exclusive backend guess. Existing
`GetFirewallState` remains the firewalld-specific zone query, and `UfwStatus`
remains ufw-specific. Neither is a general host-firewall verdict.

The first change for [#239](https://github.com/lacs-project/sysknife/issues/239)
does not add rule mutation or automatically refuse installed ufw tooling based
on a probe result. Mutating parity needs a separate design for tables, chains,
handles and rollback. Live Debian validation remains separate from fixture
tests and from distro eligibility.
