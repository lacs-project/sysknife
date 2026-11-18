// Shared fixtures for the tests that drive the real wizard (index.js) in a
// scratch git repository. Not a test file: the `npm test` glob is tests/*.test.mjs.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const setupDir = path.resolve(here, '..');

export function initGitRepo(cwd) {
  execFileSync('git', ['init'], { cwd, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd, stdio: 'ignore' });
}

/** Environment for the wizard: scratch HOME, no provider variables inherited. */
export function wizardEnv(cwd) {
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
  return childEnv;
}

/**
 * Source for a CommonJS bootstrap that stubs the daemon installer, then loads
 * the real index.js with the given wizard arguments.
 */
export function bootstrapSource(setupArgs) {
  const entry = path.join(setupDir, 'index.js');
  return [
    "if (typeof process.getuid !== 'function') process.getuid = () => 1000;",
    `const daemonInstaller = require(${JSON.stringify(path.join(setupDir, 'install-daemon.js'))});`,
    'daemonInstaller.installDaemonService = async () => '
      + "({ mode: 'skip', daemonInstalled: false, manualSteps: ['Start manually: fixture'] });",
    `process.argv = [process.execPath, ${JSON.stringify(entry)}, ...${JSON.stringify(setupArgs)}];`,
    `require(${JSON.stringify(entry)});`,
  ].join('\n');
}

/** Write the bootstrap into `dir` and return its path. */
export function writeBootstrap(dir, setupArgs) {
  const file = path.join(dir, 'wizard-bootstrap.cjs');
  fs.writeFileSync(file, bootstrapSource(setupArgs));
  return file;
}
