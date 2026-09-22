#!/usr/bin/env bash
# Exercise the local gate orchestration without running privileged operations,
# installing dependencies, or recursively executing the discovered test scripts.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
python3 - <<'PY'
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path.cwd()
SOURCE = (ROOT / 'scripts/ci-local.sh').read_text(encoding='utf-8')


def functions(*names):
    result = []
    for name in names:
        match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
        if not match:
            raise AssertionError('missing production function: ' + name)
        result.append(match.group())
    return '\n'.join(result)


def bash(code, root=ROOT):
    # Pass a POSIX path through the invoking shell, including under Git Bash.
    env = dict(os.environ, TEST_ROOT=root.as_posix())
    return subprocess.run([os.environ.get('BASH_EXE', 'bash'), '-c', 'set -euo pipefail\nrepo_root="$TEST_ROOT"\n' + code],
                          env=env, text=True, capture_output=True)


class LocalGates(unittest.TestCase):
    def test_action_pin_verifier_failure_is_a_hard_gate(self):
        code = functions('record', 'run_step', 'run_hygiene_group') + '''
RESULTS=(); hard_failures=0
have() { return 1; }
python3() { :; }
npm() { :; }
run_shell_tests() { :; }
bash() { [[ "$1" != */verify-action-pins.sh ]]; }
run_hygiene_group
printf 'failures=%s\\n' "$hard_failures"
printf '%s\\n' "${RESULTS[@]}"
'''
        result = bash(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('failures=1', result.stdout)
        self.assertIn('FAIL  hygiene: verify-action-pins.sh', result.stdout)

    def test_hygiene_runs_every_discovered_and_ci_shell_test(self):
        code = functions('run_hygiene_group')
        # Include any extracted discovery function: the real hygiene entrypoint
        # still decides whether to call it, so deleting that call fails this test.
        if 'run_shell_tests() {' in SOURCE:
            code += '\n' + functions('run_shell_tests')
        code += '''
have() { return 1; }
record() { :; }
run_step() { shift; if [[ "${1:-}" == bash && "${2:-}" == *.test.sh ]]; then printf '%s\\n' "${2#"$repo_root/"}"; fi; }
run_hygiene_group
'''
        result = bash(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = [line for line in result.stdout.splitlines() if line.startswith('tests/')]
        disk = {str(p.relative_to(ROOT)).replace('\\', '/')
                for d in ('release', 'e2e') for p in (ROOT / 'tests' / d).glob('*.test.sh')}
        ci = set()
        for workflow in (ROOT / '.github/workflows').glob('*.yml'):
            ci.update(re.findall(r'tests/(?:release|e2e)/[\w-]+\.test\.sh', workflow.read_text(encoding='utf-8')))
        self.assertTrue(disk, 'empty discovery must never pass')
        self.assertTrue(ci, 'empty CI extraction must never pass')
        self.assertEqual(set(actual), disk)
        self.assertEqual(len(actual), len(set(actual)), 'a test must run exactly once')
        self.assertFalse(ci - set(actual), 'CI tests missing locally: ' + str(ci - set(actual)))

    def test_new_file_is_discovered_and_empty_directory_fails(self):
        code = functions('record', 'run_shell_tests') + '''
RESULTS=(); hard_failures=0
run_step() { printf '%s\\n' "$*"; }
run_shell_tests
printf 'failures=%s\\n' "$hard_failures"
'''
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for directory in ('release', 'e2e'):
                (root / 'tests' / directory).mkdir(parents=True)
            result = bash(code, root)
            self.assertIn('failures=1', result.stdout)
            (root / 'tests/release/future-guard.test.sh').touch()
            result = bash(code, root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('future-guard.test.sh', result.stdout)
            self.assertIn('failures=0', result.stdout)

    def test_required_postgres_skip_is_in_final_summary(self):
        code = functions('record', 'run_postgres_contract_group', 'print_summary')
        code += '''
RESULTS=(); hard_failures=0; required_skips=(); mode=full
run_postgres=true
unset SYSKNIFE_TEST_POSTGRES_URL
have() { return 1; }
run_postgres_contract_group
print_summary
'''
        result = bash(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = result.stdout.split('ci-local summary', 1)[1]
        for text in ('REQUIRED', 'postgres-contract', 'SYSKNIFE_TEST_POSTGRES_URL', 'podman', 'INCOMPLETE'):
            self.assertIn(text, summary)
        self.assertNotIn('ci-local: PASS', summary)
        explicit = bash(code.replace('run_postgres=true', 'run_postgres=false'))
        self.assertIn('INCOMPLETE', explicit.stdout)

    def test_podman_precedes_docker(self):
        code = functions('record', 'run_postgres_contract_group') + '''
RESULTS=(); hard_failures=0; required_skips=(); run_postgres=true
POSTGRES_CONTAINER_NAME=test; POSTGRES_HOST_PORT=5433
unset SYSKNIFE_TEST_POSTGRES_URL
have() { return 0; }
podman() { printf 'podman %s\\n' "$*" >&2; return 1; }
docker() { printf 'docker was selected\\n' >&2; return 1; }
run_postgres_contract_group
'''
        result = bash(code)
        self.assertIn('podman run', result.stderr)
        self.assertNotIn('docker was selected', result.stderr)


unittest.main(verbosity=2)
PY
