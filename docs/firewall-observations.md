# Firewall observations

Use `GetFirewallBackendState` for a general firewall-state question. It probes
nftables JSON, `ufw status verbose`, and `firewall-cmd --list-all`. It reports
observed frontends and hooked nftables rules, preserving the individual probe
output excerpts and failure status. `query_firewall` uses this action during planning.

The helper computes summaries from complete probe output before bounding the
diagnostics. State, backend observations, nftables counts and the safety note
precede `probes`. Each stdout excerpt is limited to 1,024 JSON-encoded bytes,
each stderr excerpt to 512, including escaping and the explicit
`[truncated by firewall-state]` marker. This leaves the complete JSON response
below the planner's 8 KiB cap, including for non-ASCII or escape-heavy output.
Small outputs remain unchanged. Excerpts can still contain firewall topology
and are sent to the configured model; run the read-only commands locally for
complete output rather than relying on these diagnostic excerpts.

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
