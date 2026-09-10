# Action compatibility

Host eligibility, mechanism compatibility, and planner preference answer different
questions. The constants in `sysknife-core::action_family` separate them:

- `DEBIAN_ONLY_ACTIONS` covers apt/dpkg and the Debian GRUB interface.
- `UBUNTU_ONLY_ACTIONS` covers Canonical services, release upgrades, Ubuntu PPAs,
  and the Ubuntu reboot sentinel. A Debian family or `ID_LIKE=ubuntu` hint does
  not establish Ubuntu identity.
- `FEDORA_ONLY_ACTIONS` covers rpm-ostree/DNF mechanisms.
- `NON_CANONICAL_ON_DEBIAN` withholds firewalld/toolbox from the entire Debian
  family's planner. `NON_CANONICAL_ON_DEBIAN_HOST` additionally withholds
  snap/netplan/Multipass on non-Ubuntu Debian-family hosts.
- `NON_CANONICAL_ON_FEDORA` keeps the Fedora planner on its existing defaults.
  Portable mechanisms such as ufw, AppArmor, fail2ban, Flatpak and distrobox can
  still execute when the operator has installed and configured their tools.

Only the hard lists feed the daemon and CLI mechanism compatibility fences.
The shared `action_requires_supported_host` predicate also includes portable
tools for CLI host eligibility and unknown-family catalogue filtering. Those
hosts must not reach approval for mutations the daemon will refuse. This
conservative client gate withholds portable reads too; it does not restrict
portable tools on eligible Ubuntu or Fedora Atomic hosts.

At the daemon, portable Observer reads such as `UfwStatus` and `SnapList` no
longer require distro detection after leaving the hard lists. This widens
read-only inspection; mutations still require an eligible host, and the
Low-risk mutating `AptUpdate` remains hard-fenced.

Ubuntu Core is not an eligible host. Its Debian family tag does not make apt
available: the planner limits its catalogue to actions outside the shared
host-policy predicate, as it does for an unknown family. This does not claim
Ubuntu Core execution support.

The MCP surface uses the same routing checks and withholds hard-restricted actions when
detection fails. The planner receives an explicit distribution ID alongside the
family; display text never grants Ubuntu capabilities.

The action reference's Distro column describes the default supported catalogue,
including preferences. It is not a claim that a portable tool cannot be installed
elsewhere. The default Ubuntu and Fedora catalogues remain unchanged by this split.

Debian is still ineligible under `DistroId::is_supported()`. This change does not
enable its mutations or claim live Debian validation. PPAs contain packages built
for an Ubuntu series, even on Debian releases that provide add-apt-repository.
`CheckPendingReboot` reads `/var/run/reboot-required`, normally produced by
Ubuntu's update-notifier. A missing file is not sufficient evidence on Debian;
the action stays Ubuntu-only pending validation of a Debian producer or backend.
