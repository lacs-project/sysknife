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
        self.assertEqual(len(grants), 9)
        for grant in grants:
            self.assertRegex(grant, r'/action-steps (firewall|group-add|group-remove|snap-install-hold|ssh-add|ssh-remove|flatpak|podman|toolbox) \*$')

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


unittest.main(verbosity=2)
PY
