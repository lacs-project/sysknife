#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
python3 - <<'PY'
from pathlib import Path
import re
import os
import runpy
import subprocess
import tempfile
import types
import sys
import unittest
from unittest import mock

helper = runpy.run_path('packaging/sysknife-action-steps')
# runpy returns a copy; functions keep the original globals dictionary.
helper = helper['main'].__globals__


class ShellGrants(unittest.TestCase):
    def test_no_shell_or_runuser_grant(self):
        grants = [line for line in Path('packaging/sysknife-sudoers').read_text(encoding='utf-8').splitlines()
                  if line.strip() and not line.lstrip().startswith('#')]
        for grant in grants:
            self.assertIsNone(re.search(r'/(?:sh|bash|dash|runuser)(?:\s|$)', grant), grant)

    def test_no_unrestricted_helper_grant(self):
        grants = [line for line in Path('packaging/sysknife-sudoers').read_text(encoding='utf-8').splitlines()
                  if line.startswith('sysknife ') and '/action-steps' in line]
        self.assertEqual(len(grants), 23)
        for grant in grants:
            self.assertRegex(grant, r'/action-steps (firewall|group-add|group-remove|snap-install-hold|ssh-add|ssh-remove|flatpak|podman|toolbox|user-create|user-lock|user-unlock|unit|signal|user-delete|group-create|group-delete|password-aging|lv-extend|lv-create|lv-snapshot|apt|rpm-ostree) \*$')

    def test_no_useradd_usermod_or_unit_verb_grant_remains(self):
        # The escapes GHSA-j9c3-j2qr-65c4 named matched the "narrowed" grants
        # `/usr/sbin/useradd --create-home *`, `/usr/sbin/usermod --lock *` and
        # `/usr/bin/systemctl start *`, because sudoers matches the arguments as
        # one concatenated string and a trailing `*` accepts further options.
        # Those grants are gone; if one comes back, this says so here as well as
        # in tests/sudoers_grants_match_argv.rs.
        text = Path('packaging/sysknife-sudoers').read_text(encoding='utf-8')
        live = [l for l in text.splitlines() if l.startswith('sysknife ')]
        for pattern in (r'/usr/sbin/useradd\b', r'/usr/sbin/usermod\b',
                        r'/usr/bin/systemctl (start|stop|restart|reload|enable|disable|mask|unmask)\b'):
            offenders = [l for l in live if re.search(pattern, l)]
            self.assertEqual(offenders, [], f'{pattern} is granted directly again: {offenders}')


    def test_fixed_sequence_stops_at_failure(self):
        for args, expected in [
            (['firewall', 'public', 'ssh', 'add-service'],
             [['/usr/bin/firewall-cmd', '--permanent', '--zone=public', '--add-service=ssh'], ['/usr/bin/firewall-cmd', '--reload']]),
            (['snap-install-hold', 'firefox', 'stable'],
             [['/usr/bin/snap', 'install', '--channel=stable', 'firefox'], ['/usr/bin/snap', 'refresh', '--hold', 'firefox']]),
        ]:
            with mock.patch.dict(helper, run=mock.Mock()) as patched:
                helper['main'](args)
                self.assertEqual(patched['run'].call_args_list, [mock.call(v) for v in expected])
            runner = mock.Mock(side_effect=subprocess.CalledProcessError(42, expected[0]))
            with mock.patch.dict(helper, run=runner):
                with self.assertRaises(subprocess.CalledProcessError):
                    helper['main'](args)
                self.assertEqual(runner.call_count, 1)

    def test_rejects_arbitrary_commands_options_and_extra_arguments(self):
        bad = [[], ['exec', '/bin/sh'], ['firewall', 'public', 'ssh', 'reload'],
               ['firewall', 'x;id', 'ssh', 'add-service'], ['snap-install-hold', '--dangerous', 'stable'],
               ['group-add', 'alice', 'wheel\nroot'], ['ssh-add', 'alice', 'ssh-ed25519 a\nroot'],
               ['podman', 'alice', 'run', '--privileged', 'image'],
               ['toolbox', 'alice', 'run', 'sh'], ['flatpak', 'alice', 'run', '--command=sh', 'app'],
               ['ssh-remove', 'alice', 'ssh-ed25519 a', '/etc/passwd']]
        runner = mock.Mock(side_effect=AssertionError('must not execute'))
        with mock.patch.dict(helper, run=runner, drop_to_user=runner):
            for args in bad:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    helper['main'](args)

    def test_user_tool_grammar_and_drop_before_exec(self):
        cases = [('podman', ['ps', '--all', '--format', 'json']),
                 ('podman', ['create', '--name', 'demo', 'registry.example/demo:latest']),
                 ('podman', ['inspect', 'demo']), ('toolbox', ['list']),
                 ('toolbox', ['create', '--container', 'demo', '--release', '41', '--image', 'fedora:41']),
                 ('flatpak', ['install', '--user', '-y', 'flathub', 'org.example.App']),
                 ('flatpak', ['update', '--user', '-y']),
                 ('flatpak', ['remote-add', '--user', '--if-not-exists', 'demo', 'https://example.org/repo'])]
        for tool, args in cases:
            events = []
            with mock.patch.dict(helper, drop_to_user=lambda user: events.append(('drop', user))):
                with mock.patch.object(os, 'execve', side_effect=lambda *a: events.append(('exec', a))):
                    helper['main']([tool, 'alice', *args])
            self.assertEqual(events[0], ('drop', 'alice'))
            self.assertEqual(events[1][1][:2], ('/usr/bin/' + tool, ['/usr/bin/' + tool, *args]))

    def test_key_access_occurs_after_drop(self):
        events = []
        def drop(user):
            events.append('drop')
            return types.SimpleNamespace(pw_dir='/home/alice')
        with mock.patch.dict(helper, drop_to_user=drop, edit_key=lambda *a: events.append(('edit', a))):
            helper['main'](['ssh-add', 'alice', 'ssh-ed25519 AAAA...'])
        self.assertEqual(events, ['drop', ('edit', (os.path.join('/home/alice', '.ssh', 'authorized_keys'), 'ssh-ed25519 AAAA...', True))])

    def test_group_materialization_failure_prevents_membership_change(self):
        for op in ('group-add', 'group-remove'):
            runner = mock.Mock()
            with mock.patch.dict(helper, run=runner,
                                 ensure_local_group=mock.Mock(side_effect=KeyError('missing'))):
                with self.assertRaises(KeyError):
                    helper['main']([op, 'alice', 'wheel'])
                runner.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'Linux group-file semantics')
    def test_group_materialization_is_exact_and_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'group'
            path.write_text('wheel-extra:x:9:alice\n')
            real_open = os.open
            def opened(name, flags):
                self.assertEqual(name, '/etc/group')
                return real_open(path, flags)
            group = types.SimpleNamespace(gr_name='wheel', gr_passwd='x', gr_gid=10, gr_mem=['bob'])
            with mock.patch('grp.getgrnam', return_value=group), mock.patch.object(os, 'open', side_effect=opened):
                helper['ensure_local_group']('wheel')
                helper['ensure_local_group']('wheel')
            self.assertEqual(path.read_text(), 'wheel-extra:x:9:alice\nwheel:x:10:bob\n')

    def test_drop_order_and_root_refusal(self):
        account = types.SimpleNamespace(pw_name='alice', pw_uid=1234, pw_gid=4567,
                                        pw_dir='/home/alice', pw_shell='/bin/bash')
        events = []
        pwd = types.SimpleNamespace(getpwnam=lambda name: account)
        with mock.patch.dict('sys.modules', pwd=pwd), mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.multiple(os, initgroups=lambda *a: events.append('groups'),
                                     setgid=lambda *a: events.append('gid'),
                                     setuid=lambda *a: events.append('uid'),
                                     getuid=lambda: 1234, geteuid=lambda: 1234,
                                     chdir=lambda *a: events.append('home'),
                                     umask=lambda *a: None, create=True):
                helper['drop_to_user']('alice')
                self.assertEqual(events, ['groups', 'gid', 'uid', 'home'])
                self.assertEqual(os.environ['HOME'], '/home/alice')
                self.assertEqual(os.environ['XDG_RUNTIME_DIR'], '/run/user/1234')
                account.pw_uid = 0
                with self.assertRaises(ValueError):
                    helper['drop_to_user']('alice')

    @unittest.skipUnless(os.name == 'posix', 'Linux filesystem semantics')
    def test_literal_key_edits_preserve_inode_mode_and_refuse_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'authorized_keys'
            key = 'ssh-ed25519 .*'
            original = 'ssh-ed25519 AAAA alice@example.com\n' + key + '\n'
            path.write_text(original)
            path.chmod(0o640)
            before = path.stat()
            helper['edit_key'](path, key, False)
            self.assertEqual(path.read_text(), 'ssh-ed25519 AAAA alice@example.com\n')
            helper['edit_key'](path, key, True)
            helper['edit_key'](path, key, True)
            self.assertEqual(path.read_text(), original)
            self.assertEqual((path.stat().st_ino, path.stat().st_mode), (before.st_ino, before.st_mode))
            link = Path(d) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                helper['edit_key'](link, key, True)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0,
                         'real credential-drop test requires a root test subprocess')
    def test_real_drop_cannot_regain_root_or_write_through_a_symlink(self):
        import pwd
        account = pwd.getpwnam('nobody')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            root.chmod(0o755)
            home = root / 'home'
            ssh = home / '.ssh'
            ssh.mkdir(parents=True)
            for path in (home, ssh):
                os.chown(path, account.pw_uid, account.pw_gid)
                path.chmod(0o700)
            protected = root / 'root-only'
            protected.write_text('must remain unchanged\n')
            protected.chmod(0o600)
            source = '''
import os,pwd,runpy,sys,types
m=runpy.run_path(sys.argv[1]); account=pwd.getpwnam('nobody')
# Substitute only the fixture home; use real NSS identity and real set*id calls.
pwd.getpwnam=lambda name: types.SimpleNamespace(pw_name=account.pw_name,pw_uid=account.pw_uid,pw_gid=account.pw_gid,pw_dir=sys.argv[2],pw_shell=account.pw_shell)
failed=False
try: m['main'](['ssh-add','nobody','ssh-ed25519 AAAA fixture'])
except OSError: failed=True
assert failed == (sys.argv[3]=='symlink')
assert os.getuid()==account.pw_uid and os.geteuid()==account.pw_uid
assert os.getgid()==account.pw_gid and 0 not in os.getgroups()
try: os.setuid(0)
except PermissionError: pass
else: raise AssertionError('root can be regained')
'''
            command = [sys.executable, '-I', '-c', source,
                       str(Path('packaging/sysknife-action-steps').resolve()), str(home)]
            result = subprocess.run([*command, 'normal'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            keys = ssh / 'authorized_keys'
            self.assertEqual(keys.stat().st_uid, account.pw_uid)
            self.assertEqual(keys.read_text(), 'ssh-ed25519 AAAA fixture\n')
            keys.unlink()
            keys.symlink_to(protected)
            result = subprocess.run([*command, 'symlink'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(protected.read_text(), 'must remain unchanged\n')


class UserAndUnitVerbs(unittest.TestCase):
    """The verbs that replaced those grants, and what they refuse."""

    def argv_for(self, args):
        with mock.patch.dict(helper, run=mock.Mock()) as patched:
            helper['main'](args)
            return [call.args[0] for call in patched['run'].call_args_list]

    def test_builds_the_argv_the_daemon_used_to_build_itself(self):
        for args, expected in [
            (['user-create', 'alice'],
             [['/usr/sbin/useradd', '--create-home', 'alice']]),
            (['user-create', 'alice', '--home-dir', '/home/alice', '--shell', '/bin/bash'],
             [['/usr/sbin/useradd', '--create-home', '--home-dir', '/home/alice',
               '--shell', '/bin/bash', 'alice']]),
            (['user-lock', 'alice'], [['/usr/sbin/usermod', '--lock', 'alice']]),
            (['user-unlock', 'alice'], [['/usr/sbin/usermod', '--unlock', 'alice']]),
            (['unit', 'start', 'nginx.service'],
             [['/usr/bin/systemctl', 'start', 'nginx.service']]),
            (['unit', 'stop', 'nginx.service'],
             [['/usr/bin/systemctl', 'stop', 'nginx.service']]),
            (['unit', 'mask', 'debug-shell.service'],
             [['/usr/bin/systemctl', 'mask', 'debug-shell.service']]),
        ]:
            with self.subTest(args=args):
                self.assertEqual(self.argv_for(args), expected)

    def test_refuses_what_the_wildcard_grants_admitted(self):
        bad = [
            # useradd: every one of these matched `useradd --create-home *`.
            ['user-create', 'alice', '-o'],
            ['user-create', 'alice', '-o', '-u', '0'],
            ['user-create', '-o', '-u', '0', 'backdoor'],
            ['user-create', 'alice', '--uid', '0'],
            ['user-create', 'alice', '--home-dir'],
            ['user-create', 'alice', '--home-dir', '../etc/skel'],
            ['user-create', 'alice', '--home-dir', '/home/../root'],
            ['user-create', 'alice', '--home-dir', 'home/alice'],
            ['user-create', 'alice', '--shell', '-o'],
            ['user-create', 'alice', '--shell', '/bin/sh', '--shell', '/bin/bash'],
            # usermod: matched `usermod --lock *`.
            ['user-lock', '-o'],
            ['user-lock', 'alice', 'extra'],
            ['user-unlock', 'alice', '-o', '-u', '0'],
            # systemctl: matched `systemctl start *` and `systemctl <verb> *`.
            ['unit', 'start', 'debug-shell.service'],
            ['unit', 'restart', 'rescue.target'],
            ['unit', 'enable', 'RESCUE.SOCKET'],
            ['unit', 'unmask', 'emergency'],
            ['unit', 'link', '/tmp/evil.service'],
            ['unit', 'start', '../etc/passwd'],
            ['unit', 'start', '-x.service'],
            ['unit', 'start', 'nginx.service', 'extra'],
        ]
        runner = mock.Mock(side_effect=AssertionError('must not execute'))
        with mock.patch.dict(helper, run=runner):
            for args in bad:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    helper['main'](args)

    def test_refuses_to_lock_or_unlock_a_critical_account(self):
        # The daemon refuses to lock root, daemon, bin, sys, sudo and adm
        # (CRITICAL_ACCOUNTS in validate.rs). This branch checked only the
        # name's shape, so a direct `sudo action-steps user-lock root` locked
        # root, and user-unlock reopened a root account locked on purpose.
        runner = mock.Mock(side_effect=AssertionError('usermod must not run'))
        with mock.patch.dict(helper, run=runner):
            for op in ('user-lock', 'user-unlock'):
                for name in sorted(self.daemon_critical_accounts()):
                    with self.subTest(op=op, name=name), self.assertRaises(ValueError):
                        helper['main']([op, name])
        runner.assert_not_called()

    def daemon_critical_accounts(self):
        rust = Path('crates/sysknife-daemon/src/actions/validate.rs').read_text(encoding='utf-8')
        decl = re.search(r'const CRITICAL_ACCOUNTS:\s*&\[&str\]\s*=\s*&\[(.*?)\];', rust, re.S)
        self.assertIsNotNone(decl, 'CRITICAL_ACCOUNTS not found; this check inspected nothing')
        names = set(re.findall(r'"([^"]+)"', decl.group(1)))
        self.assertTrue(names, 'CRITICAL_ACCOUNTS parsed empty; refusing to compare against nothing')
        return names

    def test_critical_accounts_are_the_daemon_own_list(self):
        # Derived, not restated, for the same reason as ROOT_SHELL_UNITS below.
        self.assertEqual(set(helper.get('CRITICAL_ACCOUNTS', ())), self.daemon_critical_accounts())

    def test_account_names_follow_validated_username(self):
        # validated_username refuses a leading `.` and any `..`, because names
        # reach /home/<name>/ paths. This helper accepted `..` and `.x`.
        runner = mock.Mock(side_effect=AssertionError('must not execute'))
        with mock.patch.dict(helper, run=runner):
            for name in ('..', '.', '.hidden', 'a..b', '-x', ''):
                for args in (['user-lock', name], ['user-create', name],
                             ['group-add', name, 'wheel'], ['group-add', 'alice', name]):
                    with self.subTest(args=args), self.assertRaises(ValueError):
                        helper['main'](args)
        for name in ('alice', 'a.b', '_svc', 'deploy-1', 'a' * 32):
            with self.subTest(name=name):
                self.assertEqual(helper['username'](name), name)

    def test_root_shell_denylist_is_the_daemon_own_list(self):
        # Derived, not restated. The grub-kargs helper kept its own copy of this
        # idea and drifted to three entries while the daemon had five, which is
        # GHSA-f8vp-j3jh-7wjx. Reading the Rust source is what stops a repeat.
        rust = Path('crates/sysknife-daemon/src/actions/validate.rs').read_text(encoding='utf-8')
        decl = re.search(r'ROOT_SHELL_UNITS:\s*&\[&str\]\s*=\s*&\[(.*?)\];', rust, re.S)
        self.assertIsNotNone(decl, 'ROOT_SHELL_UNITS not found; this check inspected nothing')
        daemon_units = set(re.findall(r'"([^"]+)"', decl.group(1)))
        self.assertTrue(daemon_units, 'ROOT_SHELL_UNITS parsed empty; refusing to compare against nothing')
        self.assertLessEqual(daemon_units, set(helper['ROOT_SHELL_UNITS']))
        # Behavioural, so agreement between two lists is not the only evidence.
        runner = mock.Mock(side_effect=AssertionError('must not execute'))
        with mock.patch.dict(helper, run=runner):
            for unit in sorted(daemon_units):
                for spelling in (unit, f'{unit}.service', f'{unit}.target', unit.upper()):
                    for verb in ('start', 'restart', 'enable', 'unmask'):
                        with self.subTest(unit=spelling, verb=verb), self.assertRaises(ValueError):
                            helper['main'](['unit', verb, spelling])

    def rust_list(self, name):
        rust = Path('crates/sysknife-daemon/src/actions/validate.rs').read_text(encoding='utf-8')
        decl = re.search(name + r':\s*&\[&str\]\s*=\s*&\[(.*?)\];', rust, re.S)
        self.assertIsNotNone(decl, f'{name} not found; this check inspected nothing')
        values = set(re.findall(r'"([^"]+)"', decl.group(1)))
        self.assertTrue(values, f'{name} parsed empty; refusing to compare against nothing')
        return values

    def test_power_state_denylist_is_the_daemon_own_list(self):
        # StartService and RestartService are Medium (Dev). `reboot.target`
        # passed both copies of the screen, so a Dev caller reached the outcome
        # of RebootSystem, which is High (GHSA-68v6-p23h-fwcf).
        daemon_units = self.rust_list('POWER_STATE_UNITS')
        self.assertLessEqual(daemon_units, set(helper['POWER_STATE_UNITS']))
        runner = mock.Mock(side_effect=AssertionError('must not execute'))
        with mock.patch.dict(helper, run=runner):
            for unit in sorted(daemon_units):
                for spelling in (unit, f'{unit}.service', f'{unit}.target', unit.upper()):
                    for verb in ('start', 'restart', 'enable', 'unmask'):
                        with self.subTest(unit=spelling, verb=verb), self.assertRaises(ValueError):
                            helper['main'](['unit', verb, spelling])
        self.assertEqual(self.argv_for(['unit', 'stop', 'reboot.target']),
                         [['/usr/bin/systemctl', 'stop', 'reboot.target']])

    def test_protected_units_refuse_stop_and_restart(self):
        # Stopping sysknife-daemon, auditd or ssh is not something the Dev tier
        # may do; MaskService on the same units is High.
        exact = self.rust_list('RESOURCE_LIMIT_PROTECTED_UNITS')
        prefixes = self.rust_list('RESOURCE_LIMIT_PROTECTED_PREFIXES')
        self.assertLessEqual(exact, set(helper['PROTECTED_UNITS']))
        self.assertLessEqual(prefixes, set(helper['PROTECTED_UNIT_PREFIXES']))
        spellings = [u + '.service' for u in sorted(exact)] + [
            'SSHD.SERVICE', 'sshd@1.service', 'systemd-journald-audit.socket',
            'audit-rules.service']
        runner = mock.Mock(side_effect=AssertionError('must not execute'))
        with mock.patch.dict(helper, run=runner):
            for unit in spellings:
                for verb in ('stop', 'restart'):
                    with self.subTest(unit=unit, verb=verb), self.assertRaises(ValueError):
                        helper['main'](['unit', verb, unit])
        self.assertEqual(self.argv_for(['unit', 'start', 'ssh.service']),
                         [['/usr/bin/systemctl', 'start', 'ssh.service']])
        self.assertEqual(self.argv_for(['unit', 'restart', 'nginx.service']),
                         [['/usr/bin/systemctl', 'restart', 'nginx.service']])



class SignalVerb(unittest.TestCase):
    """`kill -s *` admitted `kill -s KILL -1` and `kill -s KILL 1`
    (GHSA-8rx7-g2jg-5pxg). The helper is the only screen on a direct call."""

    def test_signals_a_pid_or_a_process_group(self):
        import signal as sig
        for args, expected in [
            (['signal', 'TERM', '4242'], (4242, sig.SIGTERM)),
            (['signal', 'KILL', '-4242'], (-4242, sig.SIGKILL)),
            (['signal', 'HUP', '2'], (2, sig.SIGHUP)),
            (['signal', 'INT', '-2147483647'], (-2147483647, sig.SIGINT)),
        ]:
            with self.subTest(args=args), mock.patch.object(os, 'kill') as kill:
                helper['main'](args)
                kill.assert_called_once_with(*expected)

    def test_refuses_every_process_init_and_the_caller_group(self):
        bad = [['signal', 'KILL', '-1'], ['signal', 'KILL', '1'], ['signal', 'KILL', '0'],
               ['signal', 'KILL', '-0'], ['signal', 'KILL', '--1'], ['signal', 'KILL', '01'],
               ['signal', 'KILL', '-01'], ['signal', 'KILL', '2147483648'],
               ['signal', 'KILL', '-2147483648'], ['signal', 'KILL', '12a'],
               ['signal', 'KILL', ' 12'], ['signal', 'STOP', '4242'], ['signal', '9', '4242'],
               ['signal', '-s', 'KILL', '4242'], ['signal', 'KILL', '--', '-1'],
               ['signal', 'KILL']]
        with mock.patch.object(os, 'kill', side_effect=AssertionError('must not signal')):
            for args in bad:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    helper['main'](args)

    def test_signal_list_is_the_daemon_own_list(self):
        rust = Path('crates/sysknife-daemon/src/executor.rs').read_text(encoding='utf-8')
        body = re.search(r'fn validated_kill_signal\(.*?\n}\n', rust, re.S)
        self.assertIsNotNone(body, 'validated_kill_signal not found; this check inspected nothing')
        daemon = set(re.findall(r'"([A-Z]+)" => Ok', body.group(0)))
        self.assertTrue(daemon, 'validated_kill_signal parsed empty')
        self.assertEqual(daemon, set(helper['SIGNALS']))



class ShadowAndLvmVerbs(unittest.TestCase):
    """The verbs that replaced the bare userdel, groupadd, groupdel, chage,
    lvextend and lvcreate grants (GHSA-8rx7-g2jg-5pxg). shadow-utils honours
    `-R <chroot>` even after `--`, and `lvextend --config` names the fsadm
    binary `-r` runs as root, so no sudoers spelling could narrow them."""

    def argv_for(self, args):
        with mock.patch.dict(helper, run=mock.Mock()) as patched:
            helper['main'](args)
            return [call.args[0] for call in patched['run'].call_args_list]

    def test_builds_the_argv_the_daemon_used_to_build_itself(self):
        for args, expected in [
            (['user-delete', 'alice'], [['/usr/sbin/userdel', 'alice']]),
            (['group-create', 'devs'], [['/usr/sbin/groupadd', 'devs']]),
            (['group-create', '--system', 'devs'], [['/usr/sbin/groupadd', '--system', 'devs']]),
            (['group-delete', 'devs'], [['/usr/sbin/groupdel', 'devs']]),
            (['password-aging', 'alice', '-M', '90'], [['/usr/bin/chage', '-M', '90', 'alice']]),
            (['password-aging', 'alice', '-M', '90', '-m', '1', '-W', '7'],
             [['/usr/bin/chage', '-M', '90', '-m', '1', '-W', '7', 'alice']]),
            (['lv-extend', 'ubuntu-vg', 'root', '+10G'],
             [['/usr/sbin/lvextend', '-L', '+10G', '-r', 'ubuntu-vg/root']]),
            (['lv-create', 'vg0', 'data', '20G'],
             [['/usr/sbin/lvcreate', '-L', '20G', '-n', 'data', 'vg0']]),
            (['lv-snapshot', 'vg0', 'root', 'root-snap', '5G'],
             [['/usr/sbin/lvcreate', '-s', '-L', '5G', '-n', 'root-snap', 'vg0/root']]),
        ]:
            with self.subTest(args=args):
                self.assertEqual(self.argv_for(args), expected)

    def test_refuses_what_the_bare_grants_admitted(self):
        bad = [
            ['user-delete', '-R', '/tmp/x', 'alice'], ['user-delete', '--', '-R'],
            ['user-delete', '-r'], ['user-delete', 'alice', 'bob'], ['user-delete', 'root'],
            ['user-delete', 'sudo'],
            ['group-create', '-o', '-g', '0', 'rootgrp'], ['group-create', '-o'],
            ['group-create', '--system'], ['group-create', 'devs', '--system'],
            ['group-create', '--gid', '0'], ['group-create', '-R', '/tmp/x', 'devs'],
            ['group-delete', '-R', '/tmp/x', 'devs'], ['group-delete', '-f'],
            ['group-delete', 'sudo'], ['group-delete', 'shadow'],
            ['password-aging', 'alice'], ['password-aging', 'alice', '-R', '/tmp/x'],
            ['password-aging', 'root', '-E', '0'], ['password-aging', 'alice', '-d', '0'],
            ['password-aging', 'alice', '-M', '100000'], ['password-aging', 'alice', '-M', '-1'],
            ['password-aging', 'alice', '-M', '1', '-M', '2'], ['password-aging', 'alice', '-M'],
            ['password-aging', '-M', '90', 'alice'], ['password-aging', 'alice', '-M', '9x'],
            ['lv-extend', 'vg0', 'root', '--config=global/fsadm_executable=/tmp/x'],
            ['lv-extend', 'vg0', 'root', '-1G'], ['lv-extend', 'vg0', 'root', '+50%FREE'],
            ['lv-extend', 'vg0', '-n', '+1G'], ['lv-extend', 'vg0/x', 'root', '+1G'],
            ['lv-extend', 'vg0', 'root', '+1G', '--config=x'],
            ['lv-create', 'vg0', 'data', '1G', '--type', 'thin-pool'],
            ['lv-create', '--config=x', 'data', '1G'], ['lv-create', 'vg0', '.', '1G'],
            ['lv-snapshot', 'vg0', 'root', '5G'], ['lv-snapshot', 'vg0', 'root', 'snap', '1.'],
        ]
        runner = mock.Mock(side_effect=AssertionError('must not execute'))
        with mock.patch.dict(helper, run=runner):
            for args in bad:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    helper['main'](args)

    def test_critical_lists_are_the_daemon_own_lists(self):
        rust = Path('crates/sysknife-daemon/src/actions/validate.rs').read_text(encoding='utf-8')
        for rust_name, helper_name in (('CRITICAL_ACCOUNTS', 'CRITICAL_ACCOUNTS'),
                                       ('CRITICAL_GROUPS', 'CRITICAL_GROUPS')):
            decl = re.search(rust_name + r':\s*&\[&str\]\s*=\s*&\[(.*?)\];', rust, re.S)
            self.assertIsNotNone(decl, f'{rust_name} not found; this check inspected nothing')
            names = set(re.findall(r'"([^"]+)"', decl.group(1)))
            self.assertTrue(names, f'{rust_name} parsed empty')
            self.assertLessEqual(names, set(helper[helper_name]))


class AptVerb(unittest.TestCase):
    """The verb that replaced `env DEBIAN_FRONTEND=... NEEDRESTART_MODE=a
    /usr/bin/apt-get *`. That grant took any arguments after apt-get, so
    `apt-get -o APT::Update::Pre-Invoke::=<cmd> update` ran <cmd> as root with no
    preview, no approval receipt and no audit row. sudoers cannot say "and no
    options", so the helper builds the whole argv from an allowlist."""

    APT_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
               'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'a'}
    CORPUS = 'crates/sysknife-daemon/tests/data/apt-package-parity.txt'
    APT_GET, APT_MARK = '/usr/bin/apt-get', '/usr/bin/apt-mark'
    # What stops apt falling back to a regular expression for an operand that is not an
    # exact package name. Undocumented in apt.conf(5); present in apt 2.0.10 to 3.2.0.
    PATTERN_ONLY = ['-o', 'APT::Cmd::Pattern-Only=1']

    def calls_for(self, args):
        # exact_package asks the real apt-cache or dpkg-query; its own tests are below.
        with mock.patch.dict(helper, run=mock.Mock(), exact_package=mock.Mock()) as patched:
            helper['main'](args)
            return [(call.args[0], call.kwargs.get('env')) for call in patched['run'].call_args_list]

    def test_builds_the_argv_the_daemon_used_to_build_itself(self):
        APT_GET, APT_MARK, PATTERN_ONLY = self.APT_GET, self.APT_MARK, self.PATTERN_ONLY
        for args, expected in [
            (['apt', 'update'], [APT_GET, *PATTERN_ONLY, 'update']),
            (['apt', 'dist-upgrade'], [APT_GET, *PATTERN_ONLY, 'dist-upgrade', '-y']),
            (['apt', 'autoremove'], [APT_GET, *PATTERN_ONLY, 'autoremove', '-y']),
            (['apt', 'install', 'curl'], [APT_GET, *PATTERN_ONLY, 'install', '-y', '--', 'curl']),
            (['apt', 'install', 'g++'], [APT_GET, *PATTERN_ONLY, 'install', '-y', '--', 'g++']),
            (['apt', 'install', 'python3.12'],
             [APT_GET, *PATTERN_ONLY, 'install', '-y', '--', 'python3.12']),
            (['apt', 'install', 'nginx=1.24.0-1'],
             [APT_GET, *PATTERN_ONLY, 'install', '-y', '--', 'nginx=1.24.0-1']),
            (['apt', 'remove', 'curl'], [APT_GET, *PATTERN_ONLY, 'remove', '-y', '--', 'curl']),
            (['apt', 'purge', 'curl'], [APT_GET, *PATTERN_ONLY, 'purge', '-y', '--', 'curl']),
            (['apt', 'remove', 'g++:amd64'],
             [APT_GET, *PATTERN_ONLY, 'remove', '-y', '--', 'g++:amd64']),
            (['apt', 'hold', 'curl'], [APT_MARK, *PATTERN_ONLY, 'hold', '--', 'curl']),
            (['apt', 'unhold', 'curl'], [APT_MARK, *PATTERN_ONLY, 'unhold', '--', 'curl']),
            (['apt', 'hold', 'g++:amd64'], [APT_MARK, *PATTERN_ONLY, 'hold', '--', 'g++:amd64']),
        ]:
            with self.subTest(args=args):
                self.assertEqual(self.calls_for(args), [(expected, self.APT_ENV)])

    def test_refuses_what_the_wildcard_grant_admitted(self):
        bad = [
            # `-o` and `-c` name a hook or a config file apt runs as root.
            ['apt', 'update', '-o', 'APT::Update::Pre-Invoke::=/bin/sh'],
            ['apt', '-o', 'APT::Update::Pre-Invoke::=/bin/sh', 'update'],
            ['apt', 'update', '-oAPT::Update::Pre-Invoke::=/bin/sh'],
            ['apt', '--option=APT::Update::Pre-Invoke::=/bin/sh', 'update'],
            ['apt', 'update', '-c', '/tmp/evil.conf'],
            ['apt', '-c', '/tmp/evil.conf', 'update'],
            ['apt', '--config-file=/tmp/evil.conf', 'update'],
            ['apt', 'install', '-o', 'Dir::Bin::dpkg=/tmp/x', 'curl'],
            ['apt', 'install', 'curl', '-o', 'Dir::Bin::dpkg=/tmp/x'],
            ['apt', 'remove', 'curl', '-c', '/tmp/evil.conf'],
            ['apt', 'dist-upgrade', '-o', 'Dir::Bin::dpkg=/tmp/x'],
            ['apt', 'autoremove', '-o', 'APT::Update::Post-Invoke::=/bin/sh'],
            # No option the daemon never sends, and no flag the helper adds itself.
            ['apt', 'install', '-y', 'curl'], ['apt', 'install', '--', 'curl'],
            ['apt', 'dist-upgrade', '-y'], ['apt', 'autoremove', '-y'],
            ['apt', 'install', '--reinstall', 'curl'], ['apt', 'install', '-s', 'curl'],
            ['apt', '--version'], ['apt', '--help'], ['apt', '-y'], ['apt', '--'],
            # Wrong argument counts.
            ['apt'], ['apt', 'install'], ['apt', 'remove'], ['apt', 'purge'], ['apt', 'hold'], ['apt', 'unhold'],
            ['apt', 'hold', 'curl', 'vim'], ['apt', 'unhold', 'curl', 'vim'],
            ['apt', 'hold', '-o', 'Dir::Bin::dpkg=/tmp/x'], ['apt', 'hold', 'curl', '-o', 'Dir::Bin::dpkg=/tmp/x'],
            ['apt', 'hold', '--', 'curl'], ['apt', 'unhold', '--', 'curl'],
            ['apt', 'hold', '-oAPT::Update::Pre-Invoke::=/bin/sh'], ['apt', 'hold', '--reinstall'],
            ['apt', 'hold', 'curl+'], ['apt', 'hold', 'curl-'], ['apt', 'unhold', 'curl+'], ['apt', 'unhold', 'curl-'],
            ['apt', 'hold', '/tmp/x.deb'], ['apt', 'unhold', 'curl\n'], ['apt', 'hold', ''],
            ['apt', 'showhold'], ['apt', 'markauto', 'curl'], ['apt', 'manual', 'curl'], ['apt', 'auto', 'curl'],
            ['apt', 'update', 'curl'], ['apt', 'autoremove', 'curl'],
            ['apt', 'install', 'curl', 'vim'], ['apt', 'remove', 'curl', 'vim'],
            # apt-get subcommands the daemon never sends.
            ['apt', 'upgrade'], ['apt', 'full-upgrade'], ['apt', 'reinstall', 'curl'],
            ['apt', 'source', 'curl'], ['apt', 'build-dep', 'curl'], ['apt', 'download', 'curl'],
            ['apt', 'clean'], ['apt', 'autoclean'], ['apt', 'check'], ['apt', 'satisfy', 'x'],
            ['apt', 'dselect-upgrade'], ['apt', 'changelog', 'curl'], ['apt', 'indextargets'],
            ['apt', 'install-deb', 'x'], ['apt', 'UPDATE'], ['apt', 'Install', 'curl'],
            ['apt', ' update'], ['apt', 'update\n'], ['apt', ''],
            # Package slots: an option, a path, a local file, a glob, a newline, an empty string.
            ['apt', 'install', '-oAPT::Update::Pre-Invoke::=/bin/sh'], ['apt', 'install', '--reinstall'],
            ['apt', 'install', '/tmp/x.deb'], ['apt', 'install', './x.deb'], ['apt', 'install', 'x.deb'],
            ['apt', 'install', 'x.rpm'], ['apt', 'install', 'nginx/noble'], ['apt', 'install', 'ng*'],
            ['apt', 'install', 'curl\n'], ['apt', 'install', ''], ['apt', 'install', ' curl'],
            ['apt', 'remove', '-oAPT::Update::Pre-Invoke::=/bin/sh'], ['apt', 'purge', '/tmp/x.deb'],
            # A trailing `^` installs a whole task.
            ['apt', 'install', 'ubuntu-desktop^'], ['apt', 'install', 'task-xfce^'],
            ['apt', 'remove', 'task-xfce^'], ['apt', 'purge', 'task-xfce^'],
            ['apt', 'hold', 'task-xfce^'], ['apt', 'unhold', 'task-xfce^'], ['apt', 'install', 'a^b'],
            # A trailing modifier inverts the operation (GHSA-8rx7 residual).
            ['apt', 'install', 'linux-image-generic-'], ['apt', 'install', 'curl-'],
            ['apt', 'remove', 'curl+'], ['apt', 'purge', 'curl+'],
            ['apt', 'remove', 'curl-'], ['apt', 'purge', 'curl-'], ['apt', 'remove', 'g++'],
        ]
        runner = mock.Mock(side_effect=AssertionError('must not execute'))
        # exact_package is stubbed so these refusals can only come from the grammar: with the
        # real one behind it, a validator that let `curl-` through would still be stopped by
        # the existence check, and this test would pass over a broken validator.
        with mock.patch.dict(helper, run=runner, exact_package=mock.Mock()):
            for args in bad:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    helper['main'](args)
        runner.assert_not_called()

    def test_the_callers_environment_never_reaches_apt(self):
        # APT_CONFIG names a config file apt runs hooks from, and LD_PRELOAD loads
        # a library. sudo's env_reset usually drops them, but the helper has to hold
        # without relying on that: it hands apt-get an environment of its own.
        hostile = {'APT_CONFIG': '/tmp/evil.conf', 'LD_PRELOAD': '/tmp/evil.so',
                   'PATH': '/tmp/bin:/usr/bin', 'DEBIAN_FRONTEND': 'readline',
                   'NEEDRESTART_MODE': 'i', 'http_proxy': 'http://203.0.113.7:3128'}
        completed = subprocess.CompletedProcess([], 0)
        with mock.patch.dict(os.environ, hostile), mock.patch.dict(helper, exact_package=mock.Mock()), \
                mock.patch.object(subprocess, 'run', return_value=completed) as ran:
            helper['main'](['apt', 'install', 'curl'])
        ran.assert_called_once_with(
            ['/usr/bin/apt-get', *self.PATTERN_ONLY, 'install', '-y', '--', 'curl'],
            check=True, env=self.APT_ENV)

    def test_every_operand_argv_makes_apt_resolve_exact_names_only(self):
        # `.` and `+` are legal in package names (python3.12, g++) and are also regular
        # expression metacharacters, so no character class can refuse `linux-image.+` while
        # accepting `libstdc++6`. When an operand is not an exact name, apt falls back to a
        # regular expression and acts on every package it matches. The option below turns
        # the fallback off; the helper, not the caller, supplies it.
        for verb in ('install', 'remove', 'purge', 'hold', 'unhold'):
            with self.subTest(verb=verb):
                (argv, _), = self.calls_for(['apt', verb, 'curl'])
                self.assertEqual(argv[1:3], self.PATTERN_ONLY, argv)
                self.assertEqual(argv.count('-o'), 1, argv)
                self.assertEqual(argv[-2:], ['--', 'curl'], argv)
        # Every other apt-get argv the helper builds carries it too.
        for verb in ('update', 'dist-upgrade', 'autoremove'):
            with self.subTest(verb=verb):
                (argv, _), = self.calls_for(['apt', verb])
                self.assertEqual(argv[:3], [self.APT_GET, *self.PATTERN_ONLY], argv)
                self.assertEqual(argv.count('-o'), 1, argv)

    def test_operands_are_checked_for_an_exact_package_before_apt_runs(self):
        # Defence in depth: the option above is undocumented, so the helper also asks apt-cache
        # or dpkg-query whether the operand names exactly one real package, and refuses if not.
        refuse = mock.Mock(side_effect=ValueError('not exactly one existing package'))
        for verb in ('install', 'remove', 'purge', 'hold', 'unhold'):
            runner = mock.Mock(side_effect=AssertionError('apt must not run'))
            with self.subTest(verb=verb), mock.patch.dict(helper, run=runner, exact_package=refuse):
                with self.assertRaises(ValueError):
                    helper['main'](['apt', verb, 'curl'])
            runner.assert_not_called()
        for verb in ('install', 'remove', 'purge', 'hold', 'unhold'):
            check = mock.Mock()
            with self.subTest(verb=verb), mock.patch.dict(helper, run=mock.Mock(), exact_package=check):
                helper['main'](['apt', verb, 'curl'])
            check.assert_called_once_with(verb, 'curl')
        # No operand, nothing to check.
        for verb in ('update', 'dist-upgrade', 'autoremove'):
            check = mock.Mock()
            with self.subTest(verb=verb), mock.patch.dict(helper, run=mock.Mock(), exact_package=check):
                helper['main'](['apt', verb])
            check.assert_not_called()

    def test_the_existence_queries_run_with_the_helpers_own_environment(self):
        # apt-cache and dpkg-query read APT_CONFIG like apt-get does, so they get the same
        # environment as the command they guard and never the caller's.
        completed = subprocess.CompletedProcess([], 0, stdout='Package: curl\n')
        with mock.patch.dict(os.environ, {'APT_CONFIG': '/tmp/evil.conf'}), \
                mock.patch.object(subprocess, 'run', return_value=completed) as ran:
            helper['exact_package']('install', 'curl')
        ran.assert_called_once_with(['/usr/bin/apt-cache', 'show', '--no-all-versions', '--', 'curl'],
                                    capture_output=True, text=True, env=self.APT_ENV)

    def test_exact_package_accepts_only_the_package_it_was_asked_about(self):
        def answer(code, out):
            return mock.Mock(return_value=(code, out))
        cache = '/usr/bin/apt-cache'
        query = '/usr/bin/dpkg-query'
        # install asks apt-cache, which prints one Package: line per package it selects.
        for out in ('Package: curl\nVersion: 8.5\n\n', 'Package: nginx\nVersion: 1\n'):
            name = 'curl' if 'curl' in out else 'nginx'
            with mock.patch.dict(helper, capture=answer(0, out)) as patched:
                helper['exact_package']('install', name)
                patched['capture'].assert_called_once_with(
                    [cache, 'show', '--no-all-versions', '--', name])
        with mock.patch.dict(helper, capture=answer(0, 'Package: nginx\nVersion: 1\n')) as patched:
            helper['exact_package']('install', 'nginx=1.24.0-1')
            helper['exact_package']('install', 'nginx:amd64')
            self.assertEqual(patched['capture'].call_args_list[0].args[0][-1], 'nginx=1.24.0-1')
            self.assertEqual(patched['capture'].call_args_list[1].args[0][-1], 'nginx:amd64')
        bad_install = [(0, 'Package: curl\n\nPackage: curl-doc\n'),   # a regular expression matched more
                       (0, 'Package: curl-doc\n'),                       # or matched something else
                       (0, ''), (100, ''), (100, 'Package: curl\n'), (1, 'Package: curl\n')]
        for code, out in bad_install:
            with self.subTest(code=code, out=out), mock.patch.dict(helper, capture=answer(code, out)):
                with self.assertRaises(ValueError):
                    helper['exact_package']('install', 'curl')
        # remove, purge, hold and unhold ask dpkg-query, with the name and arch but not the version.
        for verb in ('remove', 'purge', 'hold', 'unhold'):
            with self.subTest(verb=verb):
                with mock.patch.dict(helper, capture=answer(0, 'curl\n')) as patched:
                    helper['exact_package'](verb, 'curl')
                    patched['capture'].assert_called_once_with([query, '-W', '-f=${Package}\\n', '--', 'curl'])
                with mock.patch.dict(helper, capture=answer(0, 'libc6\nlibc6\n')):
                    helper['exact_package'](verb, 'libc6')  # one name on two architectures
                with mock.patch.dict(helper, capture=answer(0, 'g++\n')) as patched:
                    helper['exact_package'](verb, 'g++:amd64')
                    self.assertEqual(patched['capture'].call_args.args[0][-1], 'g++:amd64')
                with mock.patch.dict(helper, capture=answer(0, 'nginx\n')) as patched:
                    helper['exact_package'](verb, 'nginx=1.24.0-1')
                    self.assertEqual(patched['capture'].call_args.args[0][-1], 'nginx')
                for code, out in [(0, 'curl\ncurl-doc\n'), (0, 'curl-doc\n'), (0, ''), (1, ''), (1, 'curl\n')]:
                    with self.subTest(code=code, out=out), mock.patch.dict(helper, capture=answer(code, out)):
                        with self.assertRaises(ValueError):
                            helper['exact_package'](verb, 'curl')

    def test_the_option_that_stops_regex_expansion_works_on_the_real_apt(self):
        # The option is undocumented in apt.conf(5), and apt's maintainer has said it may go.
        # An apt that ignores an unknown option would bring the regular expression fallback
        # back with no sign of it, so this runs the helper's own argv against the real
        # apt-get in simulate mode (-s: no lock, no change) and fails when the option stops
        # working. Skipped where apt-get or dpkg-query is missing.
        import shutil
        if not (os.path.exists(self.APT_GET) and shutil.which('dpkg-query')):
            self.skipTest('apt-get and dpkg-query are required')
        listed = subprocess.run(['dpkg-query', '-W', '-f=${Status}|${Package}\n'],
                                capture_output=True, text=True, check=True).stdout
        installed = [line.split('|', 1)[1] for line in listed.splitlines()
                     if line.split('|', 1)[0].endswith(' installed')]
        plain = sorted(n for n in installed if re.fullmatch(r'[a-z][a-z0-9-]{4,}', n))
        self.assertTrue(plain, 'no installed package with a plain name; this check inspected nothing')
        regex_operand = plain[0][:-1] + '.'
        self.assertNotIn(regex_operand, installed)
        env = dict(helper['APT_ENV'], LANG='C')

        def simulate(argv):
            self.assertEqual(argv[0], self.APT_GET)
            run = subprocess.run([argv[0], '-s', *argv[1:]], capture_output=True, text=True, env=env)
            return run.returncode, run.stdout + run.stderr

        # Control: without the option this apt resolves the operand as a regular expression.
        _, out = simulate([self.APT_GET, 'remove', '-y', '--', regex_operand])
        if 'Unable to locate package' in out:
            self.skipTest('this apt has no regular expression fallback to turn off')
        self.assertRegex(out, r'(?m)^(Remv|Purg) |selecting')
        # The helper's argv must refuse the same operand.
        for verb in ('remove', 'purge', 'install'):
            with self.subTest(verb=verb):
                code, out = simulate(helper['apt_argv']([verb, regex_operand]))
                self.assertNotEqual(code, 0, out)
                self.assertIn('Unable to locate package', out)
                self.assertNotRegex(out, r'(?m)^(Inst|Remv|Purg) ')
        # The exact-name check refuses the same operand without relying on the option: apt-cache,
        # run WITHOUT the option, expands the regular expression, and the Package: names it
        # prints are not the operand.
        for verb in ('install', 'remove', 'purge', 'hold', 'unhold'):
            with self.subTest(check=verb), self.assertRaises(ValueError):
                helper['exact_package'](verb, regex_operand)
        for verb in ('install', 'remove', 'purge', 'hold', 'unhold'):
            with self.subTest(check=verb):
                helper['exact_package'](verb, plain[0])
        # Names that really contain `.` or `+` must still resolve.
        dotted = sorted(n for n in installed if re.fullmatch(r'[a-z0-9][a-z0-9+.-]*[a-z0-9]', n)
                        and re.search(r'[.+]', n))
        for name in dotted[:3]:
            with self.subTest(exact=name):
                code, out = simulate(helper['apt_argv'](['install', name]))
                self.assertNotIn('Unable to locate package', out)
                # apt's errors start a line with 'E: '. A bare substring test also
                # matches the 'NOTE: This is only a simulation!' banner apt 3.x
                # prints to a non-root caller, which failed on every name.
                self.assertIsNone(re.search(r'^E: ', out, re.MULTILINE), out)
                for verb in ('install', 'remove', 'purge', 'hold', 'unhold'):
                    helper['exact_package'](verb, name)

    def test_a_failing_apt_get_stops_the_verb_with_its_exit_status(self):
        failure = subprocess.CalledProcessError(100, ['/usr/bin/apt-get', 'update'])
        with mock.patch.dict(helper, run=mock.Mock(side_effect=failure), exact_package=mock.Mock()):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                helper['main'](['apt', 'update'])
        self.assertEqual(caught.exception.returncode, 100)

    def test_verbs_are_the_ones_apt_rs_sends(self):
        # Derived from the daemon, not restated: a verb the daemon starts sending
        # without a helper branch fails at runtime after the operator approved it,
        # and a verb the helper accepts that the daemon never sends is dead surface.
        rust = Path('crates/sysknife-daemon/src/actions/apt.rs').read_text(encoding='utf-8')
        # Production code only: the unit tests below `#[cfg(test)]` spell the same
        # argv, and reading them would hide a constructor that stopped sending a verb.
        self.assertEqual(rust.count('#[cfg(test)]'), 1, 'apt.rs test module marker not found')
        production = rust.split('#[cfg(test)]')[0]
        sent = set(re.findall(r'ACTION_STEPS,\s*"apt",\s*"([a-z-]+)"', production))
        self.assertTrue(sent, 'apt.rs sends no apt verb; this check inspected nothing')
        accepted = set(helper['APT_BARE']) | set(helper['APT_WITH_PACKAGE'])
        self.assertEqual(sent, accepted)

    def test_package_operands_agree_with_the_daemon_corpus(self):
        # The daemon's validated_install_package and validated_unmodified_package
        # read the same file in validate.rs's unit tests. Two copies of a rule drift
        # (GHSA-f8vp-j3jh-7wjx); one corpus both must satisfy is what stops that.
        runner = mock.Mock()
        seen, checked = set(), 0
        lines = Path(self.CORPUS).read_text(encoding='utf-8').splitlines()
        with mock.patch.dict(helper, run=runner, exact_package=mock.Mock()):
            for number, line in enumerate(lines, 1):
                if not line or line.startswith('#'):
                    continue
                parts = line.split(' ', 2)
                self.assertEqual(len(parts), 3, f'corpus line {number} does not parse: {line!r}')
                verb, verdict, operand = parts
                self.assertIn(verdict, ('ok', 'refuse'), f'corpus line {number}')
                self.assertIn(verb, ('install', 'remove', 'purge', 'hold', 'unhold'), f'corpus line {number}')
                runner.reset_mock()
                with self.subTest(line=number, verb=verb, operand=operand):
                    if verdict == 'ok':
                        helper['main'](['apt', verb, operand])
                        runner.assert_called_once()
                    else:
                        with self.assertRaises(ValueError):
                            helper['main'](['apt', verb, operand])
                        runner.assert_not_called()
                seen.add((verb, verdict))
                checked += 1
        self.assertGreaterEqual(checked, 50, 'the corpus was truncated or not parsed')
        for verb in ('install', 'remove', 'purge', 'hold', 'unhold'):
            for verdict in ('ok', 'refuse'):
                self.assertIn((verb, verdict), seen, f'the corpus has no `{verb} {verdict}` line')

    def test_package_length_limit_matches_the_daemon(self):
        runner = mock.Mock()
        with mock.patch.dict(helper, run=runner, exact_package=mock.Mock()):
            helper['main'](['apt', 'install', 'a' * 128])
            runner.assert_called_once()
            with self.assertRaises(ValueError):
                helper['main'](['apt', 'install', 'a' * 129])

    def live_grants(self):
        text = Path('packaging/sysknife-sudoers').read_text(encoding='utf-8')
        return [l for l in text.splitlines() if l.startswith('sysknife ')]

    def test_no_apt_get_grant_remains(self):
        # The grant was `env DEBIAN_FRONTEND=... NEEDRESTART_MODE=a /usr/bin/apt-get *`.
        # Pinning the env prefix did nothing against `-o`, and a sibling that keeps
        # the old line alive would leave the escape open, so the line must be gone.
        live = self.live_grants()
        self.assertTrue(live, 'parsed no sudoers grants; this check inspected nothing')
        offenders = [l for l in live if 'apt-get' in l or 'apt-mark' in l]
        self.assertEqual(offenders, [], f'apt-get or apt-mark is granted directly again: {offenders}')
        wildcard = [l for l in live if re.search(r'apt-(get|mark)\b.*\*\s*$', l)]
        self.assertEqual(wildcard, [])
        env_grants = [l for l in live if re.search(r'NOPASSWD:\s*/usr/bin/env\b', l)]
        self.assertEqual(env_grants, [], '`env` runs any command as root; it must not be granted')

    def test_apt_is_granted_only_through_the_helper(self):
        grants = [l for l in self.live_grants() if re.search(r'/action-steps apt\b', l)]
        self.assertEqual(grants, ['sysknife ALL=(root) NOPASSWD: /usr/lib/sysknife/action-steps apt *'])


class RpmOstreeVerb(unittest.TestCase):
    """The verb that replaced the `/usr/bin/rpm-ostree <subcommand> *` grants.

    A trailing `*` takes rpm-ostree's own options and operands, so the sysknife
    account could append any kernel argument, layer a local package whose
    scriptlets run as root, or rebase onto any image, with no preview, no approval
    receipt and no audit row. sudoers cannot say "and no options", so every
    rpm-ostree call that takes an operand goes through `action-steps rpm-ostree`,
    which rebuilds the argv from an allowlist."""

    R = '/usr/bin/rpm-ostree'
    CORPUS = 'crates/sysknife-daemon/tests/data/rpm-ostree-parity.txt'
    SYSTEM_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}

    def calls_for(self, args):
        with mock.patch.dict(helper, run=mock.Mock()) as patched:
            helper['main'](args)
            return [call.args[0] for call in patched['run'].call_args_list]

    def test_builds_the_argv_the_daemon_used_to_build_itself(self):
        R = self.R
        for args, expected in [
            (['rpm-ostree', 'install', 'podman'], [R, 'install', '--idempotent', 'podman']),
            (['rpm-ostree', 'install', 'podman', 'vim', 'g++'],
             [R, 'install', '--idempotent', 'podman', 'vim', 'g++']),
            (['rpm-ostree', 'install', 'python3.12'], [R, 'install', '--idempotent', 'python3.12']),
            (['rpm-ostree', 'uninstall', 'podman'], [R, 'uninstall', 'podman']),
            (['rpm-ostree', 'uninstall', 'podman', 'vim'], [R, 'uninstall', 'podman', 'vim']),
            (['rpm-ostree', 'replace', 'vim', 'neovim'], [R, 'install', 'neovim', '--uninstall', 'vim']),
            (['rpm-ostree', 'override-remove', 'gedit'], [R, 'override', 'remove', 'gedit']),
            (['rpm-ostree', 'rebase', 'fedora/41/x86_64/silverblue'],
             [R, 'rebase', 'fedora/41/x86_64/silverblue']),
            (['rpm-ostree', 'rebase', 'fedora:fedora/41/x86_64/silverblue'],
             [R, 'rebase', 'fedora:fedora/41/x86_64/silverblue']),
            (['rpm-ostree', 'rebase', 'ostree-image-signed:docker://quay.io/fedora/fedora-silverblue:41'],
             [R, 'rebase', 'ostree-image-signed:docker://quay.io/fedora/fedora-silverblue:41']),
            (['rpm-ostree', 'kargs'], [R, 'kargs']),
            (['rpm-ostree', 'kargs', 'append', 'nomodeset', 'delete', 'quiet'],
             [R, 'kargs', '--append=nomodeset', '--delete=quiet']),
            (['rpm-ostree', 'kargs', 'append', 'console=ttyS0,115200', 'append', 'quiet'],
             [R, 'kargs', '--append=console=ttyS0,115200', '--append=quiet']),
            # Removing a downgrade hardens the host, so it stays allowed.
            (['rpm-ostree', 'kargs', 'delete', 'mitigations=off'], [R, 'kargs', '--delete=mitigations=off']),
        ]:
            with self.subTest(args=args):
                self.assertEqual(self.calls_for(args), [expected])

    def test_refuses_what_the_wildcard_grants_admitted(self):
        bad = [
            # kargs: a root shell or a weaker boot at the next start.
            ['rpm-ostree', 'kargs', 'append', 'init=/bin/sh'],
            ['rpm-ostree', 'kargs', '--append=init=/bin/sh'],
            ['rpm-ostree', 'kargs', '--append', 'init=/bin/sh'],
            ['rpm-ostree', 'kargs', 'append', 'quiet init=/bin/sh'],
            ['rpm-ostree', 'kargs', 'append', 'INIT=/bin/sh'],
            ['rpm-ostree', 'kargs', 'append', 'rdinit=/bin/sh'],
            ['rpm-ostree', 'kargs', 'append', 'systemd.unit=debug-shell.service'],
            ['rpm-ostree', 'kargs', 'append', 'rd.systemd.unit=emergency.target'],
            ['rpm-ostree', 'kargs', 'append', 'systemd.debug_shell'],
            ['rpm-ostree', 'kargs', 'append', 'systemd.run=/tmp/x'],
            ['rpm-ostree', 'kargs', 'append', 'rd.break'],
            ['rpm-ostree', 'kargs', 'append', 'single'],
            ['rpm-ostree', 'kargs', 'append', 'emergency'],
            ['rpm-ostree', 'kargs', 'append', '3'],
            ['rpm-ostree', 'kargs', 'append', 'selinux=0'],
            ['rpm-ostree', 'kargs', 'append', 'lockdown=none'],
            ['rpm-ostree', 'kargs', 'append', 'mitigations=off'],
            ['rpm-ostree', 'kargs', 'append', 'module.sig_enforce=0'],
            ['rpm-ostree', 'kargs', 'append', 'nokaslr'],
            ['rpm-ostree', 'kargs', 'delete', 'lockdown=confidentiality'],
            ['rpm-ostree', 'kargs', 'delete', 'module.sig_enforce=1'],
            ['rpm-ostree', 'kargs', 'delete', 'selinux=1'],
            ['rpm-ostree', 'kargs', 'delete', 'kaslr'],
            ['rpm-ostree', 'kargs', 'delete', 'lockdown'], ['rpm-ostree', 'kargs', 'delete', 'mitigations'],
            ['rpm-ostree', 'kargs', 'delete', 'lsm=landlock,lockdown'], ['rpm-ostree', 'kargs', 'delete', 'audit=1'],
            ['rpm-ostree', 'kargs', 'append', 'systemd.wants=debug-shell.service'],
            ['rpm-ostree', 'kargs', 'append', 'rd.shell'], ['rpm-ostree', 'kargs', 'append', 'audit=0'],
            ['rpm-ostree', 'kargs', 'append', 'nopti'], ['rpm-ostree', 'kargs', 'append', 'lsm=landlock'],
            ['rpm-ostree', 'kargs', 'append', 'systemd.mask=auditd.service'],
            # The allowlist: anything not named is refused, whatever its spelling.
            ['rpm-ostree', 'kargs', 'append', 'foo=bar'], ['rpm-ostree', 'kargs', 'append', 'mitigations=of'],
            ['rpm-ostree', 'kargs', 'append', 'nopku'], ['rpm-ostree', 'kargs', 'append', 'spectre-v2=off'],
            ['rpm-ostree', 'kargs', 'append', 'audit=off'], ['rpm-ostree', 'kargs', 'append', 'lsm=landlock'],
            ['rpm-ostree', 'kargs', 'append', 'spectre_v2_user=off'], ['rpm-ostree', 'kargs', 'append', 'quiet=1'],
            ['rpm-ostree', 'kargs', 'delete', 'module.sig_enforce'], ['rpm-ostree', 'kargs', 'delete', 'foo=bar'],
            ['rpm-ostree', 'kargs', 'delete', 'nosmt'], ['rpm-ostree', 'kargs', 'delete', 'vsyscall=none'],
            ['rpm-ostree', 'kargs', 'append', 'resume=/dev/sdb1'], ['rpm-ostree', 'kargs', 'append', 'resume_offset=1'],
            # A listed key whose value carries a second boot-line token: only the
            # one-token check stands between it and the boot line.
            ['rpm-ostree', 'kargs', 'append', 'console=tty0 init=/bin/sh'],
            ['rpm-ostree', 'kargs', 'append', 'console=tty0\tinit=/bin/sh'],
            ['rpm-ostree', 'kargs', 'append', 'console="tty0 init=/bin/sh"'],
            ['rpm-ostree', 'kargs', 'delete', 'console=tty0 lockdown=integrity'],
            ['rpm-ostree', 'kargs', 'append', 'rd.driver.blacklist=tpm_crb'],
            ['rpm-ostree', 'kargs', 'append', 'rd.driver.blacklist=nouveau,dm_crypt'],
            ['rpm-ostree', 'kargs', 'append', '-b'], ['rpm-ostree', 'kargs', 'append', ''],
            ['rpm-ostree', 'kargs', 'append', 'quiet\n'], ['rpm-ostree', 'kargs', 'append', 'a' * 255],
            ['rpm-ostree', 'kargs', 'append', 'quiet"'], ['rpm-ostree', 'kargs', 'append', 'quiet\tinit=/bin/sh'],
            ['rpm-ostree', 'kargs', 'append'], ['rpm-ostree', 'kargs', 'delete'],
            ['rpm-ostree', 'kargs', 'append', 'quiet', 'delete'],
            ['rpm-ostree', 'kargs', 'prepend', 'quiet'], ['rpm-ostree', 'kargs', 'replace', 'quiet=1'],
            ['rpm-ostree', 'kargs', 'append-if-missing', 'quiet'], ['rpm-ostree', 'kargs', 'APPEND', 'quiet'],
            ['rpm-ostree', 'kargs', '--editor'], ['rpm-ostree', 'kargs', '--import-proc-cmdline'],
            ['rpm-ostree', 'kargs', '--deploy-index=1', 'append', 'quiet'],
            ['rpm-ostree', 'kargs', 'append=quiet'],
            # install / uninstall / replace / override-remove: a local package runs its
            # scriptlets as root in the next deployment.
            ['rpm-ostree', 'install', '/tmp/x.rpm'], ['rpm-ostree', 'install', './x.rpm'],
            ['rpm-ostree', 'install', 'x.rpm'], ['rpm-ostree', 'install', 'podman', '/tmp/x.rpm'],
            ['rpm-ostree', 'install', 'https://203.0.113.7/x.rpm'],
            ['rpm-ostree', 'install', 'file:///tmp/x.rpm'],
            ['rpm-ostree', 'install', '--idempotent', 'podman'], ['rpm-ostree', 'install', '-A', 'podman'],
            ['rpm-ostree', 'install', '--apply-live', 'podman'], ['rpm-ostree', 'install', 'podman', '-r'],
            ['rpm-ostree', 'install', 'podman', '--uninstall', 'bash'],
            ['rpm-ostree', 'install', '--', 'podman'], ['rpm-ostree', 'install', 'podman-'],
            ['rpm-ostree', 'install', 'podman\n'], ['rpm-ostree', 'install', ''],
            ['rpm-ostree', 'install', ' podman'], ['rpm-ostree', 'install', 'pod*'],
            ['rpm-ostree', 'install', 'a' * 129],
            ['rpm-ostree', 'uninstall', '--all'], ['rpm-ostree', 'uninstall', '-r', 'podman'],
            ['rpm-ostree', 'uninstall', '/tmp/x.rpm'], ['rpm-ostree', 'uninstall', 'podman', '--install=/tmp/x.rpm'],
            ['rpm-ostree', 'replace', 'vim', '/tmp/x.rpm'], ['rpm-ostree', 'replace', '/tmp/x.rpm', 'vim'],
            ['rpm-ostree', 'replace', 'vim', '--uninstall'], ['rpm-ostree', 'replace', 'vim'],
            ['rpm-ostree', 'replace', 'vim', 'neovim', 'emacs'],
            ['rpm-ostree', 'override-remove', 'gedit', '--replace=/tmp/x.rpm'],
            ['rpm-ostree', 'override-remove', '--replace', '/tmp/x.rpm'],
            ['rpm-ostree', 'override-remove', 'gedit', 'vim'], ['rpm-ostree', 'override-remove'],
            ['rpm-ostree', 'override-remove', '/tmp/x.rpm'],
            # rebase: a local repository or a local image is an arbitrary OS image.
            ['rpm-ostree', 'rebase', '/tmp/repo'], ['rpm-ostree', 'rebase', './repo'],
            ['rpm-ostree', 'rebase', '../repo'], ['rpm-ostree', 'rebase', 'fedora:../../tmp/x'],
            # rebase: an unverified image, local or remote, is any OS image the caller names.
            ['rpm-ostree', 'rebase', 'ostree-unverified-registry:quay.io/fedora/fedora-silverblue:41'],
            ['rpm-ostree', 'rebase', 'ostree-unverified-image:docker://quay.io/x:1'],
            ['rpm-ostree', 'rebase', 'ostree-unverified-image:oci:/tmp/img'],
            ['rpm-ostree', 'rebase', 'ostree-unverified-image:OCI:/tmp/img'],
            ['rpm-ostree', 'rebase', 'ostree-unverified-image:oci-archive:/tmp/img.tar'],
            ['rpm-ostree', 'rebase', 'ostree-unverified-image:dir:/tmp/img'],
            ['rpm-ostree', 'rebase', 'ostree-unverified-image:docker-archive:/tmp/img.tar'],
            ['rpm-ostree', 'rebase', 'ostree-unverified-image:containers-storage:localhost/x'],
            ['rpm-ostree', 'rebase', 'ostree-unverified-image:docker-daemon:x:latest'],
            ['rpm-ostree', 'rebase', 'ostree-unverified-image:ostree:x@/tmp/repo'],
            ['rpm-ostree', 'rebase', 'ostree-unverified-image:sif:/tmp/x.sif'],
            ['rpm-ostree', 'rebase', 'ostree-unverified-image:tarball:/tmp/x.tar'],
            ['rpm-ostree', 'rebase', 'file:///tmp/repo'], ['rpm-ostree', 'rebase', 'x:/tmp/repo'],
            ['rpm-ostree', 'rebase', '-b', 'x'], ['rpm-ostree', 'rebase', '--experimental'],
            ['rpm-ostree', 'rebase', 'fedora', '--branch=x'], ['rpm-ostree', 'rebase', 'fedora', 'x'],
            ['rpm-ostree', 'rebase'], ['rpm-ostree', 'rebase', ''], ['rpm-ostree', 'rebase', 'fedora\n'],
            ['rpm-ostree', 'rebase', 'fedora 41'], ['rpm-ostree', 'rebase', 'a' * 255],
            # Subcommands with an exact grant of their own, or none at all.
            ['rpm-ostree'], ['rpm-ostree', ''], ['rpm-ostree', 'install'], ['rpm-ostree', 'uninstall'],
            ['rpm-ostree', 'upgrade'], ['rpm-ostree', 'rollback'], ['rpm-ostree', 'cleanup', '--rollback'],
            ['rpm-ostree', 'override', 'remove', 'gedit'], ['rpm-ostree', 'override', 'replace', '/tmp/x.rpm'],
            ['rpm-ostree', 'override-replace', 'x'], ['rpm-ostree', 'override-reset', '--all'],
            ['rpm-ostree', 'status'], ['rpm-ostree', 'deploy', 'x'], ['rpm-ostree', 'apply-live'],
            ['rpm-ostree', 'usroverlay'], ['rpm-ostree', 'initramfs', '--enable'],
            ['rpm-ostree', 'initramfs-etc', '--track=/etc/x'], ['rpm-ostree', 'reset'],
            ['rpm-ostree', 'refresh-md'], ['rpm-ostree', 'compose', 'tree'], ['rpm-ostree', 'ex'],
            ['rpm-ostree', 'cancel'], ['rpm-ostree', 'INSTALL', 'podman'], ['rpm-ostree', 'install ', 'podman'],
            ['rpm-ostree', '--version'], ['rpm-ostree', '-h'],
        ]
        runner = mock.Mock(side_effect=AssertionError('must not execute'))
        with mock.patch.dict(helper, run=runner):
            for args in bad:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    helper['main'](args)
        runner.assert_not_called()

    def test_the_callers_environment_never_reaches_rpm_ostree(self):
        hostile = {'LD_PRELOAD': '/tmp/evil.so', 'PATH': '/tmp/bin:/usr/bin',
                   'RPMOSTREE_CLIENT_ID': 'x', 'G_DEBUG': 'fatal-warnings'}
        completed = subprocess.CompletedProcess([], 0)
        with mock.patch.dict(os.environ, hostile), \
                mock.patch.object(subprocess, 'run', return_value=completed) as ran:
            helper['main'](['rpm-ostree', 'install', 'podman'])
        ran.assert_called_once_with([self.R, 'install', '--idempotent', 'podman'],
                                    check=True, env=self.SYSTEM_ENV)

    def test_a_failing_rpm_ostree_stops_the_verb_with_its_exit_status(self):
        failure = subprocess.CalledProcessError(77, [self.R, 'rebase', 'fedora'])
        with mock.patch.dict(helper, run=mock.Mock(side_effect=failure)):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                helper['main'](['rpm-ostree', 'rebase', 'fedora'])
        self.assertEqual(caught.exception.returncode, 77)

    def production_rust(self, path):
        rust = Path(path).read_text(encoding='utf-8')
        # The unit tests below `#[cfg(test)]` spell the same argv, and reading them
        # would hide a constructor that stopped sending a verb.
        self.assertEqual(rust.count('#[cfg(test)]'), 1, f'{path}: test module marker not found')
        return rust.split('#[cfg(test)]')[0]

    def test_verbs_are_the_ones_the_daemon_sends(self):
        # Derived from the daemon, not restated. A verb the daemon sends without a
        # helper branch fails after the operator approved it; a verb the helper
        # accepts that the daemon never sends is surface nobody needs.
        sent = set()
        for path in ('crates/sysknife-daemon/src/actions/layering.rs',
                     'crates/sysknife-daemon/src/actions/deployment.rs'):
            sent |= set(re.findall(r'ACTION_STEPS,\s*"rpm-ostree",\s*"([a-z-]+)"', self.production_rust(path)))
        self.assertTrue(sent, 'the daemon sends no rpm-ostree verb; this check inspected nothing')
        self.assertEqual(sent, set(helper['RPM_OSTREE_VERBS']))

    def test_no_privileged_action_builds_a_direct_rpm_ostree_argv_with_an_operand(self):
        # Every `sudo rpm-ostree ...` left in the daemon must be one of the fixed argvs
        # with an exact grant. Anything else needs a wildcard to be admitted.
        fixed = {('upgrade',), ('rollback',), ('cleanup', '--rollback', '--pending'),
                 ('override', 'reset', '--all')}
        found = set()
        for path in ('crates/sysknife-daemon/src/actions/layering.rs',
                     'crates/sysknife-daemon/src/actions/deployment.rs'):
            for body in re.findall(r'command_mechanism\(\s*"sudo",\s*\[\s*"rpm-ostree",([^\]]*)\]',
                                   self.production_rust(path)):
                found.add(tuple(re.findall(r'"([^"]*)"', body)))
            self.assertNotRegex(self.production_rust(path), r'once\("rpm-ostree"\)',
                                f'{path} still chains a direct rpm-ostree argv')
        self.assertEqual(found, fixed)

    def grub(self):
        from importlib.machinery import SourceFileLoader
        import importlib.util
        loader = SourceFileLoader('grub_kargs_edit', 'packaging/sysknife-grub-kargs-edit')
        spec = importlib.util.spec_from_loader('grub_kargs_edit', loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def test_kargs_allowlist_is_the_same_in_all_three_copies(self):
        # One allowlist, three copies: executor.rs screens both actions in the
        # daemon, grub-kargs-edit screens GrubSetKargs and this verb screens
        # SetKernelArguments. Compare this copy with the other two element by element.
        grub = self.grub()
        rust = Path('crates/sysknife-daemon/src/executor.rs').read_text(encoding='utf-8')
        for name in ('KARG_FLAGS', 'KARG_HARDENING_FLAGS', 'KARG_VALUE_KEYS', 'KARG_WEAKENING'):
            with self.subTest(list=name):
                decl = re.search(rf'const {name}:\s*&\[&str\]\s*=\s*&\[(.*?)\];', rust, re.S)
                self.assertIsNotNone(decl, f'{name} not found in executor.rs')
                daemon = sorted(re.findall(r'"([^"]+)"', decl.group(1)))
                self.assertTrue(daemon, f'{name} parsed empty; this check inspected nothing')
                self.assertEqual(sorted(helper[name]), daemon)
                self.assertEqual(sorted(getattr(grub, name)), daemon)
        decl = re.search(r'const KARG_HARDENING_VALUES:\s*&\[\(&str, &\[&str\]\)\]\s*=\s*&\[(.*?)\n\];',
                         rust, re.S)
        self.assertIsNotNone(decl, 'KARG_HARDENING_VALUES not found in executor.rs')
        daemon = {k: sorted(re.findall(r'"([^"]+)"', v)) for k, v in
                  re.findall(r'\(\s*"([^"]+)",\s*&\[(.*?)\]\s*,?\s*\)', decl.group(1), re.S)}
        self.assertGreaterEqual(len(daemon), 10, 'KARG_HARDENING_VALUES parsed short')
        self.assertEqual({k: sorted(v) for k, v in helper['KARG_HARDENING_VALUES'].items()}, daemon)
        self.assertEqual({k: sorted(v) for k, v in grub.KARG_HARDENING_VALUES.items()}, daemon)
        decl = re.search(r'const KARG_LIST_VALUES:\s*&\[\(&str, &\[&str\]\)\]\s*=\s*&\[(.*?)\]\s*;',
                         rust, re.S)
        self.assertIsNotNone(decl, 'KARG_LIST_VALUES not found in executor.rs')
        daemon = {k: sorted(re.findall(r'"([^"]+)"', v)) for k, v in
                  re.findall(r'\(\s*"([^"]+)",\s*&\[(.*?)\]\s*,?\s*\)', decl.group(1), re.S)}
        self.assertTrue(daemon, 'KARG_LIST_VALUES parsed empty; this check inspected nothing')
        self.assertEqual({k: sorted(v) for k, v in helper['KARG_LIST_VALUES'].items()}, daemon)
        self.assertEqual({k: sorted(v) for k, v in grub.KARG_LIST_VALUES.items()}, daemon)

    def test_kargs_screens_decide_like_the_grub_helper(self):
        # Equal lists are not equal decisions: the screens around them could differ.
        grub = self.grub()
        tokens = ['quiet', 'nomodeset', 'console=ttyS0', 'init=/bin/sh', 'INIT=/x', 'rdinit=/x',
                  'single', 'SINGLE', 's', '1', '2', '5', '6', 'emergency', 'rescue', 'rd.emergency',
                  'systemd.unit=debug-shell.service', 'systemd.unit=multi-user.target',
                  'rd.systemd.unit=rescue.target', 'systemd.unit=runlevel1.target',
                  'systemd.debug_shell', 'systemd.debug-shell=1', 'systemd.run=/x',
                  'systemd.run_success_action=reboot', 'rd.break', 'rd.break=pre-mount', 'break',
                  'breakfast', 'selinux=0', 'selinux=1', 'enforcing=0', 'enforcing=1',
                  'security=none', 'apparmor=0', 'apparmor=01', 'apparmor=1', 'lockdown=none',
                  'lockdown=integrity', 'lockdown=confidentiality', 'mitigations=off',
                  'mitigations=auto', 'pti=off', 'pti=on', 'nosmap', 'nosmep', 'nokaslr', 'kaslr',
                  'module.sig_enforce=0', 'module.sig_enforce=1', 'module_blacklist=x',
                  'init_on_alloc=0', 'init_on_free=1', 'slab_nomerge', 'nosmt', 'debugfs=on',
                  'debugfs=off', 'iommu=off', 'intel_iommu=on', 'amd_iommu=force_isolation',
                  'vsyscall=none', 'slub_debug=FZP', 'page_poison=1', 'page_alloc.shuffle=0',
                  'randomize_kstack_offset=off', 'single=1', 'emergency=1',
                  # A bare key deletes the key's only value (ostree_kernel_args_delete).
                  'lockdown', 'module.sig_enforce', 'selinux', 'enforcing', 'apparmor',
                  'security', 'iommu', 'mitigations', 'init_on_alloc', 'lsm', 'audit',
                  'kaslr=1', 'quiet=1',
                  # Units pulled in with wants, and the remaining weakenings.
                  'systemd.wants=debug-shell.service', 'rd.systemd.wants=emergency.target',
                  'systemd.wants=sshd.service', 'lsm=landlock', 'rd.shell', 'rd.shell=0',
                  'systemd.mask=auditd.service', 'rd.systemd.mask=auditd.service',
                  'modprobe.blacklist=apparmor', 'audit=0', 'audit=1', 'nopti',
                  'nospectre_v1', 'nospectre_v2', 'spectre_v2=off', 'spectre_v2=on',
                  'spec_store_bypass_disable=off',
                  # `-` and `_` are one character in a parameter name (parameq()).
                  'spectre-v2=off', 'module-blacklist=x', 'Spec-Store-Bypass-Disable=off',
                  'rd.systemd.debug-shell', 'nospectre-bhb', 'module.sig-enforce=1',
                  'init-on-alloc=0', 'init-on-alloc=1', 'systemd.wants=foo-bar.service',
                  # Every spelling of off, and the remaining mitigation switches.
                  'audit=off', 'audit=n', 'audit=no', 'audit=false', 'AUDIT=OFF',
                  'mitigations=false', 'pti=no', 'spectre_v2=n', 'mds=off', 'mds=full', 'mds',
                  'tsx_async_abort=off', 'tsx_async_abort=full', 'mmio_stale_data=off',
                  'retbleed=off', 'retbleed=auto', 'srbds=off', 'srbds=on', 'l1tf=off',
                  'l1tf=flush', 'spectre_bhi=off', 'spectre_bhi=on', 'gather_data_sampling=off',
                  'gather_data_sampling=force', 'reg_file_data_sampling=off',
                  'reg_file_data_sampling=on', 'module.sig_enforce=no', 'init_on_free=false',
                  'nospec_store_bypass_disable', 'nospectre_bhb', 'spec_store_bypass_disable=on',
                  'apparmor=01', 'debugfs=on', 'iommu=off', 'lockdown=none', '_b',
                  # The allowlist and the spellings the denylists missed.
                  'foo=bar', 'foo', 'mitigations=of', 'nopku', 'spectre_v2_user=off', 'kpti=0',
                  'its=off', 'tsa=off', 'vmscape=off', 'noibrs', 'noibpb', 'audit=f', 'quiet=1',
                  'console=', 'splash', 'rhgb', 'nowatchdog', 'threadirqs', 'slab_nomerge',
                  'rd.driver.blacklist=nouveau', 'nvidia-drm.modeset=1', 'lockdown=integrity',
                  'module.sig_enforce=1', 'intel_iommu=on', 'amd_iommu=force_isolation', 'init_on_free=1',
                  'page_alloc.shuffle=1', 'randomize_kstack_offset=on', 'mitigations=auto',
                  'mitigations=auto,nosmt', 'pti=on', 'vsyscall=none', 'debugfs=off', 'root=/dev/sdb1',
                  'resume=/dev/sdb1', 'resume_offset=1', 'resume', 'rd.driver.blacklist=tpm_crb',
                  'rd.driver.blacklist=nvidia', 'rd.driver.blacklist=dm_crypt']

        def grub_refuses(screen, token):
            try:
                getattr(grub, screen)([token])
            except SystemExit as exc:
                return exc.code != 0
            return False

        def helper_refuses(op, token):
            with mock.patch.dict(helper, run=mock.Mock()):
                try:
                    helper['main'](['rpm-ostree', 'kargs', op, token])
                except ValueError:
                    return True
            return False

        for token in tokens:
            with self.subTest(token=token):
                self.assertEqual(helper_refuses('append', token), grub_refuses('reject_dangerous_append', token))
                self.assertEqual(helper_refuses('delete', token), grub_refuses('reject_dangerous_delete', token))

    def test_local_image_transports_are_the_daemons(self):
        rust = Path('crates/sysknife-daemon/src/actions/validate.rs').read_text(encoding='utf-8')
        block = re.search(r'pub const LOCAL_IMAGE_TRANSPORTS: &\[&str\] = &\[(.*?)\];', rust, re.S)
        self.assertIsNotNone(block, 'LOCAL_IMAGE_TRANSPORTS not found in validate.rs')
        daemon = re.findall(r'"([^"]+)"', block.group(1))
        self.assertTrue(daemon, 'LOCAL_IMAGE_TRANSPORTS parsed empty; this check inspected nothing')
        self.assertEqual(sorted(helper['LOCAL_IMAGE_TRANSPORTS']), sorted(daemon))

    def test_operands_agree_with_the_daemon_corpus(self):
        # The daemon's validated_install_package, validated_rebase_ref,
        # validated_safe_kernel_arg and validated_safe_kernel_arg_removal read the same
        # file in executor.rs's unit tests. Two copies of a rule drift; one corpus both
        # must satisfy is what stops that.
        argv_for = {
            'package': lambda v: ['rpm-ostree', 'install', v],
            'ref': lambda v: ['rpm-ostree', 'rebase', v],
            'append': lambda v: ['rpm-ostree', 'kargs', 'append', v],
            'delete': lambda v: ['rpm-ostree', 'kargs', 'delete', v],
        }
        runner = mock.Mock()
        seen, checked = set(), 0
        lines = Path(self.CORPUS).read_text(encoding='utf-8').splitlines()
        with mock.patch.dict(helper, run=runner):
            for number, line in enumerate(lines, 1):
                if not line or line.startswith('#'):
                    continue
                parts = line.split(' ', 2)
                self.assertEqual(len(parts), 3, f'corpus line {number} does not parse: {line!r}')
                kind, verdict, operand = parts
                self.assertIn(verdict, ('ok', 'refuse'), f'corpus line {number}')
                self.assertIn(kind, argv_for, f'corpus line {number}')
                runner.reset_mock()
                with self.subTest(line=number, kind=kind, operand=operand):
                    if verdict == 'ok':
                        helper['main'](argv_for[kind](operand))
                        runner.assert_called_once()
                    else:
                        with self.assertRaises(ValueError):
                            helper['main'](argv_for[kind](operand))
                        runner.assert_not_called()
                seen.add((kind, verdict))
                checked += 1
        self.assertGreaterEqual(checked, 60, 'the corpus was truncated or not parsed')
        for kind in argv_for:
            for verdict in ('ok', 'refuse'):
                self.assertIn((kind, verdict), seen, f'the corpus has no `{kind} {verdict}` line')
        # Every package verb applies the same rule as `install`.
        for verb in (['uninstall'], ['override-remove']):
            with mock.patch.dict(helper, run=mock.Mock()):
                with self.assertRaises(ValueError):
                    helper['main'](['rpm-ostree', *verb, '/tmp/x.rpm'])

    def live_grants(self):
        text = Path('packaging/sysknife-sudoers').read_text(encoding='utf-8')
        return [l for l in text.splitlines() if l.startswith('sysknife ')]

    def test_no_rpm_ostree_grant_ends_in_a_wildcard(self):
        live = self.live_grants()
        self.assertTrue(live, 'parsed no sudoers grants; this check inspected nothing')
        direct = [l for l in live if re.search(r'NOPASSWD:\s*/usr/bin/rpm-ostree\b', l)]
        self.assertTrue(direct, 'no direct rpm-ostree grant at all; the fixed argvs need one each')
        wildcard = [l for l in direct if '*' in l]
        self.assertEqual(wildcard, [], f'rpm-ostree takes any argument again: {wildcard}')
        # The fixed argvs, each granted exactly: the four actions that take no
        # operand, and the action-timeout reaper's `rpm-ostree cancel`.
        arguments = sorted(' '.join(l.split('NOPASSWD:', 1)[1].split()[1:]) for l in direct)
        self.assertEqual(arguments, sorted(['upgrade', 'rollback', 'cleanup --rollback --pending',
                                            'override reset --all', 'cancel']))

    def test_rpm_ostree_operands_are_granted_only_through_the_helper(self):
        grants = [l for l in self.live_grants() if re.search(r'/action-steps rpm-ostree\b', l)]
        self.assertEqual(grants, ['sysknife ALL=(root) NOPASSWD: /usr/lib/sysknife/action-steps rpm-ostree *'])


unittest.main(verbosity=2)
PY
