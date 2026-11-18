// The API key prompt on a real terminal. The piped-stdin tests cannot see this
// path: with a TTY, readline owns the keystrokes and draws them back unless the
// prompt mutes it. `script` gives the wizard a pty, so the transcript is what a
// person would see on screen.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { initGitRepo, wizardEnv, writeBootstrap } from './wizard-harness.mjs';

const hasScript = spawnSync('script', ['--version'], { stdio: 'ignore' }).status === 0;

const KEY = 'sk-test-KEYSECRET4242';
const CONTROL_MODEL = 'control-model-visible-echo';
const STEP_TIMEOUT_MS = 15_000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function shellQuote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/**
 * Drive the wizard on a pty. `steps` is an ordered list of
 * { prompt: RegExp, send: (write) => Promise<void> }: each step waits for its
 * prompt to appear in the transcript past the previous one, then types.
 * Resolves with the whole transcript and the exit status.
 */
function driveOnPty(cwd, steps) {
  const bootstrap = writeBootstrap(cwd, ['--claude', '--no-binary', '--daemon-mode=skip']);
  const command = `${shellQuote(process.execPath)} ${shellQuote(bootstrap)}`;
  const child = spawn('script', ['-qfec', command, '/dev/null'], {
    cwd,
    env: wizardEnv(cwd),
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let transcript = '';
  let cursor = 0;
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { transcript += chunk; });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { transcript += chunk; });

  const exited = new Promise((resolve) => {
    child.on('close', (status) => resolve(status));
  });
  const write = (text) => new Promise((resolve) => child.stdin.write(text, resolve));

  const run = (async () => {
    for (const step of steps) {
      const deadline = Date.now() + STEP_TIMEOUT_MS;
      for (;;) {
        const rest = transcript.slice(cursor);
        const hit = step.prompt.exec(rest);
        if (hit) {
          cursor += hit.index + hit[0].length;
          break;
        }
        if (Date.now() > deadline) {
          throw new Error(`prompt ${step.prompt} never appeared; transcript so far:\n${transcript}`);
        }
        await sleep(25);
      }
      await step.send(write);
    }
    return exited;
  })();

  const killer = setTimeout(() => child.kill('SIGKILL'), STEP_TIMEOUT_MS * 3);
  return run.then(
    (status) => ({ status, transcript }),
    (error) => {
      child.kill('SIGKILL');
      throw error;
    },
  ).finally(() => clearTimeout(killer));
}

async function typeSlowly(write, text) {
  for (const ch of text) {
    await write(ch);
    await sleep(5);
  }
}

function afterKey(sendKey) {
  return [
    { prompt: /LLM provider[^\n]*: /, send: (w) => w('anthropic\r') },
    { prompt: /ANTHROPIC_API_KEY: /, send: sendKey },
    // A control: ordinary prompts still echo, so a transcript without the key
    // means the prompt muted it and not that the harness cannot see typing.
    { prompt: /Model name[^\n]*: /, send: (w) => typeSlowly(w, `${CONTROL_MODEL}\r`) },
    { prompt: /Daemon socket[^\n]*: /, send: (w) => w('\r') },
    { prompt: /Add another VM\?[^\n]*: /, send: (w) => w('n\r') },
  ];
}

function scratchRepo() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'sysknife-setup-pty-'));
  initGitRepo(cwd);
  return cwd;
}

function assertKeyOnlyInConfig(cwd, result) {
  assert.ok(
    result.status === 0 || result.status === 3,
    `wizard exit status ${result.status}; transcript:\n${result.transcript}`,
  );
  assert.ok(
    result.transcript.includes(CONTROL_MODEL),
    `control: typed model name should be echoed on a pty; transcript:\n${result.transcript}`,
  );
  assert.ok(
    !result.transcript.includes('KEYSECRET'),
    `API key leaked to the terminal; transcript:\n${result.transcript}`,
  );
  const mcp = JSON.parse(fs.readFileSync(path.join(cwd, '.mcp.json'), 'utf8'));
  const env = Object.values(mcp.mcpServers)[0].env;
  assert.equal(env.ANTHROPIC_API_KEY, KEY);
  assert.equal(env.SYSKNIFE_LLM_MODEL, CONTROL_MODEL);
}

test('API key typed one character at a time is not echoed on a pty', { skip: !hasScript && 'util-linux script not installed' }, async () => {
  const cwd = scratchRepo();
  try {
    const result = await driveOnPty(cwd, afterKey((w) => typeSlowly(w, `${KEY}\r`)));
    assertKeyOnlyInConfig(cwd, result);
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

test('API key pasted with Enter in one chunk finishes the prompt and is not echoed', { skip: !hasScript && 'util-linux script not installed' }, async () => {
  const cwd = scratchRepo();
  try {
    const result = await driveOnPty(cwd, afterKey((w) => w(`${KEY}\r`)));
    assertKeyOnlyInConfig(cwd, result);
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

test('Ctrl+C at the key prompt ends the wizard without echoing the partial key', { skip: !hasScript && 'util-linux script not installed' }, async () => {
  const cwd = scratchRepo();
  try {
    const result = await driveOnPty(cwd, [
      { prompt: /LLM provider[^\n]*: /, send: (w) => w('anthropic\r') },
      { prompt: /ANTHROPIC_API_KEY: /, send: (w) => typeSlowly(w, 'sk-test-KEYSECRET\x03') },
    ]);
    assert.ok(!result.transcript.includes('KEYSECRET'), result.transcript);
    assert.ok(!fs.existsSync(path.join(cwd, '.mcp.json')), 'no config may be written after Ctrl+C');
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

test('backspace edits the hidden key before it is stored', { skip: !hasScript && 'util-linux script not installed' }, async () => {
  const cwd = scratchRepo();
  try {
    const result = await driveOnPty(
      cwd,
      afterKey((w) => typeSlowly(w, `${KEY}XY\x7f\x7f\r`)),
    );
    assertKeyOnlyInConfig(cwd, result);
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});
