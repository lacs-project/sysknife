#!/usr/bin/env bash
#
# ubuntu-command-validity.sh — check that the commands SysKnife would run on
# Ubuntu actually exist and actually parse.
#
# The unit tests prove the daemon *builds* the argv it intends to. They cannot
# prove that argv is real: a flag that does not exist, a subcommand renamed
# between releases, or a binary that is not installed all look identical to a
# passing unit test and only fail on a user's machine, after the operator has
# approved a preview promising it would work.
#
# This is also how the `apt-get` sudoers mismatch was caught: the argv was
# well-formed and every unit test passed, but sudo refused it on a real host
# because the grant spells `/usr/bin/apt-get` and the code sent a bare name.
#
# Run INSIDE an Ubuntu VM (it inspects the live system):
#
#   tests/e2e/ubuntu-vm.sh ssh 'bash -s' < tests/e2e/ubuntu-command-validity.sh
#
# Exit status: 0 if every check passes. Tools that are simply not installed are
# reported as SKIP, not failure — an action whose tool is absent fails loudly
# at runtime anyway, which is the correct behaviour.
#
# Safety: read-only or dry-run everywhere. ufw is never enabled (that would
# sever the SSH connection this script arrives on); its rule syntax is checked
# with `--dry-run`.

set -uo pipefail

pass=0
fail=0
skip=0

ok()   { printf 'OK    %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf 'FAIL  %s -- %s\n' "$1" "$2"; fail=$((fail + 1)); }
skipf(){ printf 'SKIP  %s (%s not installed)\n' "$1" "$2"; skip=$((skip + 1)); }

# Run a check, but only if the tool is present.
need() {
  local tool="$1" desc="$2"
  shift 2
  if ! command -v "$tool" >/dev/null 2>&1; then
    skipf "$desc" "$tool"
    return
  fi
  local out
  if out=$("$@" 2>&1); then
    ok "$desc"
  else
    bad "$desc" "$(printf '%s' "$out" | head -1)"
  fi
}

# Assert a flag or subcommand appears in a tool's own help output.
has_flag() {
  local tool="$1" desc="$2" flag="$3"
  shift 3
  if ! command -v "$tool" >/dev/null 2>&1; then
    skipf "$desc" "$tool"
    return
  fi
  if "$@" 2>&1 | grep -q -- "$flag"; then
    ok "$desc"
  else
    bad "$desc" "$flag absent from help output"
  fi
}

echo "== apt (simulate: no packages are changed) =="
need apt-get "apt-get update"                 sudo apt-get update -qq
need apt-get "apt-get dist-upgrade -y"        sudo apt-get -s dist-upgrade -y
need apt-get "apt-get install -y"             sudo apt-get -s install -y hello
need apt-get "apt-get remove -y"              sudo apt-get -s remove -y hello
need apt-get "apt-get purge -y"               sudo apt-get -s purge -y hello
need apt-get "apt-get autoremove -y"          sudo apt-get -s autoremove -y
need apt-mark "apt-mark hold / unhold"        sudo sh -c 'apt-mark hold bash >/dev/null && apt-mark unhold bash >/dev/null'
need apt-cache "apt-cache policy"             apt-cache policy
need apt-cache "apt-cache show"               apt-cache show bash
need apt-cache "apt-cache search"             apt-cache search bash
need dpkg      "dpkg -l"                      sh -c 'dpkg -l >/dev/null'
need apt       "apt list --upgradable"        sh -c 'apt list --upgradable 2>/dev/null >/dev/null'

echo "== sudoers grant actually matches the argv =="
# The grant is the whole reason apt-get must be spelled absolutely. If the
# sysknife user exists with the packaged sudoers installed, prove sudo accepts
# the real invocation rather than falling through to a password prompt.
if id sysknife >/dev/null 2>&1 && sudo test -f /etc/sudoers.d/sysknife; then
  if sudo -u sysknife sudo -n env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
      /usr/bin/apt-get --version >/dev/null 2>&1; then
    ok "sudo accepts the env-wrapped absolute apt-get"
  else
    bad "sudo accepts the env-wrapped absolute apt-get" "denied — grant and argv disagree"
  fi
else
  skipf "sudo grant check" "sysknife user or /etc/sudoers.d/sysknife"
fi

echo "== ufw (dry-run only — never enabled, that would cut SSH) =="
need ufw "ufw allow"          sudo ufw --dry-run allow 22
need ufw "ufw deny"           sudo ufw --dry-run deny 23
need ufw "ufw limit"          sudo ufw --dry-run limit 22
need ufw "ufw status verbose" sudo ufw status verbose
# `--force` is not advertised in `ufw --help`, so prove it parses instead:
# with no rules present ufw complains about the *rule*, not the flag. Any
# "unknown option"-style rejection would mean the argv is wrong.
if command -v ufw >/dev/null 2>&1; then
  ufw_out=$(sudo ufw --dry-run --force delete 1 2>&1 || true)
  if printf '%s' "$ufw_out" | grep -qi "could not find rule\|Rules updated\|^\*filter"; then
    ok "ufw --force delete N"
  else
    bad "ufw --force delete N" "$(printf '%s' "$ufw_out" | head -1)"
  fi
else
  skipf "ufw --force delete N" "ufw"
fi

echo "== snap =="
has_flag snap "snap install --classic" "--classic" snap install --help
has_flag snap "snap refresh --hold"    "--hold"    snap refresh --help
has_flag snap "snap refresh --unhold"  "--unhold"  snap refresh --help
need snap "snap list" sh -c 'snap list >/dev/null'

echo "== netplan =="
need netplan "netplan set"      sh -c 'netplan set --help >/dev/null'
need netplan "netplan get"      sh -c 'netplan get --help >/dev/null'
need netplan "netplan generate" sh -c 'netplan generate --help >/dev/null'

echo "== release upgrade / Ubuntu Pro =="
has_flag do-release-upgrade "do-release-upgrade -f <frontend>" "frontend" do-release-upgrade --help
need pro "pro status --all" sh -c 'pro status --all >/dev/null'
has_flag pro "pro enable --assume-yes" "--assume-yes" pro enable --help

echo "== identity, DNS, security tooling =="
need chage      "chage -l"            sudo chage -l root
need resolvectl "resolvectl status"   sh -c 'resolvectl status >/dev/null'
need aa-status  "aa-status"           sudo aa-status
need cloud-init "cloud-init status"   sh -c 'cloud-init status --long >/dev/null'
need auditctl   "auditctl -l"         sudo auditctl -l
need fail2ban-client "fail2ban-client status" sudo fail2ban-client status
need add-apt-repository "add-apt-repository --help" sh -c 'add-apt-repository --help >/dev/null'

echo "---"
printf 'pass=%d fail=%d skip=%d\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
