import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const setupDir = path.resolve(here, '..');

function initGitRepo(cwd) {
  execFileSync('git', ['init'], { cwd, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd, stdio: 'ignore' });
}

function runWizardWithKey(cwd, gitignoreBody) {
  if (gitignoreBody !== null) {
    fs.writeFileSync(path.join(cwd, '.gitignore'), gitignoreBody);
  }
  initGitRepo(cwd);

  const entry = path.join(setupDir, 'index.js');
  const setupArgs = ['--claude', '--no-binary', '--daemon-mode=skip'];
  const childEnv = { ...process.env, HOME: cwd, XDG_RUNTIME_DIR: cwd };
  for (const name of [
    'SYSKNIFE_LLM_PROVIDER',
    'ANTHROPIC_API_KEY',
    'OPENAI_API_KEY',
    'GEMINI_API_KEY',
    'GROQ_API_KEY',
    'DEEPSEEK_API_KEY',
    'MISTRAL_API_KEY',
    'XAI_API_KEY',
  ]) {
    delete childEnv[name];
  }

  const bootstrap = [
    "if (typeof process.getuid !== 'function') process.getuid = () => 1000;",
    `const daemonInstaller = require(${JSON.stringify(path.join(setupDir, 'install-daemon.js'))});`,
    "daemonInstaller.installDaemonService = async () => "
      + "({ mode: 'skip', daemonInstalled: false, manualSteps: ['Start manually: fixture'] });",
    `process.argv = [process.execPath, ${JSON.stringify(entry)}, ...${JSON.stringify(setupArgs)}];`,
    `require(${JSON.stringify(entry)});`,
  ];

  // provider, secret key, model (default), daemon socket (default), add another VM? n
  const input = 'anthropic\nsynthetic-key-for-gitignore-test\n\n\nn\n';

  return spawnSync(process.execPath, ['-e', bootstrap.join(' ')], {
    cwd,
    encoding: 'utf8',
    input,
    timeout: 30_000,
    env: childEnv,
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
      assertMcpIgnored(cwd);
      const mcp = fs.readFileSync(path.join(cwd, '.mcp.json'), 'utf8');
      assert.match(mcp, /synthetic-key-for-gitignore-test/);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
}

test('substring match alone no longer treats a comment as coverage', () => {
  const source = fs.readFileSync(path.join(setupDir, 'index.js'), 'utf8');
  assert.doesNotMatch(source, /gitignore\.includes\('\.mcp\.json'\)/);
  assert.match(source, /check-ignore/);
  assert.match(source, /secret:\s*true/);
});
