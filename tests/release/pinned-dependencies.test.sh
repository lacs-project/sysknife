#!/usr/bin/env bash
# Pinned-Dependencies contract: every install the CI and the E2E harnesses run
# is pinned by a hash, so a compromised registry entry or installer cannot
# reach a runner that holds the workflow token or a VM that holds a provider key.
#
# OpenSSF Scorecard reported eight sites that were not (ci.yml x3, ci-local.sh,
# e2e.yml, provision.sh x2, ubuntu-provision.sh). This test reads the files
# Scorecard scans and fails when one of those shapes comes back.
#
# Host-side only: parses files, needs no network, no npm and no pip.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

python3 - "$repo_root" <<'PYTHON'
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pinned-dependencies: PyYAML is required")

root = Path(sys.argv[1])
failures = []


def fail(message):
    failures.append(message)


def read(rel):
    path = root / rel
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {rel}: {error}")
        return ""


def run_blocks(rel):
    """Every `run:` string of a workflow, keyed by 'job/step name'."""
    try:
        workflow = yaml.safe_load(read(rel))
    except yaml.YAMLError as error:
        fail(f"{rel} is not valid YAML: {error}")
        return {}
    blocks = {}
    for job_name, job in (workflow or {}).get("jobs", {}).items():
        for index, step in enumerate(job.get("steps", []) if isinstance(job, dict) else []):
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                blocks[f"{job_name}/{step.get('name', index)}"] = step["run"]
    if not blocks:
        fail(f"{rel} has no run steps; the scan would be vacuous")
    return blocks


# A command is at command position at the start of a line or after a shell
# separator. That keeps a hint inside a quoted message ("install: npm install
# ...") out of the scan, which is what Scorecard's shell parser does too.
COMMAND = r"(?:^\s*|[;&|(]\s*|\bthen\s+|\bdo\s+)(?:sudo\s+(?:-\S+\s+)*)?"
NPM_UNPINNED = re.compile(COMMAND + r"npm\s+(?:install|i|add)\b", re.M)
PIP_INSTALL = re.compile(COMMAND + r"(?:python3?\s+-m\s+)?pip3?\s+install\b([^\n]*)", re.M)
# No command-position anchor here: `su - user -c 'curl ... | sh'` hides the pipe inside
# quotes, and Scorecard's parser recurses into it.
FETCH_PIPE_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|da|z)?sh\b"
)


def code_lines(text):
    """Drop whole-line comments, then fold backslash continuations onto one line."""
    kept = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return re.sub(r"\\\n[ \t]*", " ", kept)


def scan_unpinned(label, text):
    code = code_lines(text)
    if NPM_UNPINNED.search(code):
        fail(f"{label}: `npm install` resolves versions at run time; use `npm ci` against a lockfile")
    for match in PIP_INSTALL.finditer(code):
        if "--require-hashes" not in match.group(1):
            fail(f"{label}: `pip install` without --require-hashes: {match.group(0).strip()}")
    for match in FETCH_PIPE_SHELL.finditer(code):
        fail(f"{label}: downloads and pipes straight into a shell; fetch, verify the sha256, then run: {match.group(0)[:70]}")


# ---------------------------------------------------------------------------
# Lint tools: ci.yml:44-46 and scripts/ci-local.sh:202
# ---------------------------------------------------------------------------

pkg_rel = "tools/ci-node/package.json"
lock_rel = "tools/ci-node/package-lock.json"
req_rel = "tools/ci-python/requirements.txt"

try:
    package = json.loads(read(pkg_rel))
except json.JSONDecodeError as error:
    fail(f"{pkg_rel} is not valid JSON: {error}")
    package = {}
node_deps = package.get("dependencies", {})
if sorted(node_deps) != ["markdown-link-check", "markdownlint-cli2"]:
    fail(f"{pkg_rel} must pin exactly markdownlint-cli2 and markdown-link-check, found {sorted(node_deps)}")
for name, spec in node_deps.items():
    if not re.fullmatch(r"\d+\.\d+\.\d+", spec):
        fail(f"{pkg_rel}: {name} must be an exact version, not '{spec}'")
if package.get("private") is not True:
    fail(f"{pkg_rel} must be private so it can never be published")

try:
    lock = json.loads(read(lock_rel))
except json.JSONDecodeError as error:
    fail(f"{lock_rel} is not valid JSON: {error}")
    lock = {}
if lock.get("lockfileVersion", 0) < 2:
    fail(f"{lock_rel}: lockfileVersion must be 2 or newer")
packages = lock.get("packages", {})
if len(packages) < 50:
    fail(f"{lock_rel} lists {len(packages)} packages; a lockfile of two lint tools has well over 50")
if packages.get("", {}).get("dependencies", {}) != node_deps:
    fail(f"{lock_rel} root does not match {pkg_rel}; run npm install --package-lock-only")
for path, entry in packages.items():
    if path == "":
        continue
    if not str(entry.get("integrity", "")).startswith("sha512-"):
        fail(f"{lock_rel}: {path} has no sha512 integrity hash")
    if not str(entry.get("resolved", "")).startswith("https://registry.npmjs.org/"):
        fail(f"{lock_rel}: {path} does not resolve from registry.npmjs.org over https")

requirements = read(req_rel)
logical = code_lines(requirements)
pinned_names = set()
for line in (line.strip() for line in logical.splitlines()):
    if not line:
        continue
    match = re.fullmatch(r"([A-Za-z0-9._-]+)==(\d+(?:\.\d+)*)((?:\s+--hash=sha256:[0-9a-f]{64})+)", line)
    if not match:
        fail(f"{req_rel}: not an exact pin with sha256 hashes: {line[:80]}")
        continue
    pinned_names.add(match.group(1).lower())
for needed in ("yamllint", "pyyaml", "pathspec"):
    if needed not in pinned_names:
        fail(f"{req_rel} lacks {needed}; --require-hashes refuses an unlisted dependency")

guide = read("docs/developer-guide.md")
for tool, version in [("yamllint", None), ("markdownlint-cli2", node_deps.get("markdownlint-cli2")),
                      ("markdown-link-check", node_deps.get("markdown-link-check"))]:
    row = re.search(r"^\|\s*`" + re.escape(tool) + r"`\s*\|\s*([0-9.]+)\s*\|", guide, re.M)
    if not row:
        fail(f"docs/developer-guide.md has no version row for {tool}")
    elif version is not None and row.group(1) != version:
        fail(f"docs/developer-guide.md says {tool} {row.group(1)} but {pkg_rel} pins {version}")
yamllint_pin = re.search(r"^yamllint==([0-9.]+)", requirements, re.M)
yamllint_row = re.search(r"^\|\s*`yamllint`\s*\|\s*([0-9.]+)\s*\|", guide, re.M)
if yamllint_pin and yamllint_row and yamllint_pin.group(1) != yamllint_row.group(1):
    fail(f"docs/developer-guide.md says yamllint {yamllint_row.group(1)} but {req_rel} pins {yamllint_pin.group(1)}")

ci = run_blocks(".github/workflows/ci.yml")
lint = ci.get("docs-and-hygiene/Install lint tools", "")
if not lint:
    fail("ci.yml has no 'Install lint tools' step in docs-and-hygiene")
for needle in ("npm ci --prefix tools/ci-node",
               "pip install --require-hashes -r tools/ci-python/requirements.txt",
               "tools/ci-node/node_modules/.bin"):
    if needle not in lint:
        fail(f"ci.yml 'Install lint tools' must contain: {needle}")
if re.search(r"--upgrade", lint):
    fail("ci.yml 'Install lint tools' upgrades pip from the network; pip is not pinned by the hash list")

ci_local = read("scripts/ci-local.sh")
install_fn = re.search(r"^frontend_install\(\) \(\n.*?^\)", ci_local, re.M | re.S)
if not install_fn:
    fail("scripts/ci-local.sh has no frontend_install function")
elif not re.search(r"^\s*npm ci\b", install_fn.group(), re.M):
    fail("scripts/ci-local.sh frontend_install must install with `npm ci`")

# ---------------------------------------------------------------------------
# Installers: e2e.yml:129, provision.sh:88 and :113, ubuntu-provision.sh:169
# ---------------------------------------------------------------------------
# Each one now goes through tests/e2e/pinned-installers.sh, which checks a pinned
# sha256 before it runs anything. tests/e2e/pinned-installers.test.sh proves the
# helper refuses a mismatch; this part proves the four sites actually use it.

helper_rel = "tests/e2e/pinned-installers.sh"
helper_use = {
    "tests/e2e/provision.sh": ["pinned_install_rustup", "pinned_install_ollama"],
    "tests/e2e/ubuntu-provision.sh": ["pinned_install_rustup"],
}
for rel, functions in helper_use.items():
    text = code_lines(read(rel))
    if "pinned-installers.sh" not in text or not re.search(r"\bsource\b|(?:^|\s)\.\s", text):
        fail(f"{rel} does not source {helper_rel}")
    for function in functions:
        if not re.search(r"\b" + function + r"\b", text):
            fail(f"{rel} never calls {function}")
    for forbidden in ("sh.rustup.rs", "ollama.com/install.sh"):
        if forbidden in text:
            fail(f"{rel} still references {forbidden} outside the pinned helper")

e2e = run_blocks(".github/workflows/e2e.yml")
ollama_step = next((script for name, script in e2e.items() if name.endswith("/Install Ollama")), "")
if not ollama_step:
    fail("e2e.yml has no 'Install Ollama' step")
else:
    if "pinned_install_ollama" not in ollama_step or "tests/e2e/pinned-installers.sh" not in ollama_step:
        fail("e2e.yml 'Install Ollama' must source tests/e2e/pinned-installers.sh and call pinned_install_ollama")
    if "ollama.com/install.sh" in ollama_step:
        fail("e2e.yml 'Install Ollama' still references ollama.com/install.sh")

ci_steps = run_blocks(".github/workflows/ci.yml")
if not any(script.strip() == "bash tests/e2e/pinned-installers.test.sh" for script in ci_steps.values()):
    fail("ci.yml does not run tests/e2e/pinned-installers.test.sh")

# ---------------------------------------------------------------------------
# The scan itself, over every file Scorecard reads for these shapes
# ---------------------------------------------------------------------------

for rel in (".github/workflows/ci.yml", ".github/workflows/e2e.yml", ".github/workflows/release.yml"):
    for step, script in run_blocks(rel).items():
        scan_unpinned(f"{rel} [{step}]", script)
for rel in ("scripts/ci-local.sh", "tests/e2e/provision.sh", "tests/e2e/ubuntu-provision.sh",
            "tests/e2e/pinned-installers.sh"):
    scan_unpinned(rel, read(rel))

# The scanner must be able to fail: each shape it forbids, once, as a self-check.
probes = {
    "npm install --global x@1": True,
    "  sudo npm i left-pad": True,
    "npm ci --prefix tools/ci-node": False,
    "pip install yamllint==1.38.0": True,
    "python -m pip install --upgrade pip": True,
    "pip install --require-hashes -r r.txt": False,
    "curl -fsSL https://example.test/i.sh | sh": True,
    "curl --proto '=https' -sSf https://example.test/i.sh | sudo sh -s -- -y": True,
    "printf 'install: npm install --global x' >&2": False,
    "# npm install --global x": False,
}
for probe, expect in probes.items():
    before = len(failures)
    scan_unpinned("probe", probe)
    hit = len(failures) > before
    del failures[before:]
    if hit != expect:
        fail(f"scanner self-check: {probe!r} should {'be flagged' if expect else 'pass'}")

if failures:
    print("pinned-dependencies: FAIL", file=sys.stderr)
    for message in failures:
        print(f"  - {message}", file=sys.stderr)
    sys.exit(1)
print("Pinned-dependencies contract passed.")
PYTHON
