import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { initGitRepo, wizardEnv, writeBootstrap } from './wizard-harness.mjs';

function runWizardWithKey(cwd, gitignoreBody) {
  if (gitignoreBody !== null) {
    fs.writeFileSync(path.join(cwd, '.gitignore'), gitignoreBody);
  }
  initGitRepo(cwd);

  const bootstrap = writeBootstrap(cwd, ['--claude', '--no-binary', '--daemon-mode=skip']);

  // provider, secret key, model (default), daemon socket (default), add another VM? n
  const input = 'anthropic\nsynthetic-key-for-gitignore-test\n\n\nn\n';

  return spawnSync(process.execPath, [bootstrap], {
    cwd,
    encoding: 'utf8',
    input,
    timeout: 30_000,
    env: wizardEnv(cwd),
  });
}

function assertMcpIgnored(cwd) {
  const check = spawnSync('git', ['check-ignore', '-q', '--', '.mcp.json'], { cwd });
  assert.equal(check.status, 0, 'expected .mcp.json to be gitignored');
  const gitignore = fs.readFileSync(path.join(cwd, '.gitignore'), 'utf8');
  assert.match(gitignore, /^\.mcp\.json$/m);
}

for (const { label, gitignore } of [
  {
    label: 'comment that merely names .mcp.json',
    gitignore: '# .mcp.json lives in my home dir\n',
  },
  {
    label: 'negation of .mcp.json',
    gitignore: '!.mcp.json\n',
  },
  {
    label: 'longer name containing the substring',
    gitignore: '.mcp.json.bak\n',
  },
  {
    label: 'empty / missing .gitignore',
    gitignore: null,
  },
]) {
  test(`embedded API key appends .mcp.json ignore despite ${label}`, () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'sysknife-setup-gitignore-'));
    try {
      const result = runWizardWithKey(cwd, gitignore);
      const output = `${result.stdout}${result.stderr}`;
      assert.ok(result.status === 0 || result.status === 3, output);
      assert.match(output, /Appended \.mcp\.json to \.gitignore/, output);
      assert.doesNotMatch(output, /synthetic-key-for-gitignore-test/, output);
      // The append branch must not swallow the advice about the hook files.
      assert.match(output, /\.claude\/\*\.local\.md/, output);
      assertMcpIgnored(cwd);
      const mcp = fs.readFileSync(path.join(cwd, '.mcp.json'), 'utf8');
      assert.match(mcp, /synthetic-key-for-gitignore-test/);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
}
