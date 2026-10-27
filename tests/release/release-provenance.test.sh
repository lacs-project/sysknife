#!/usr/bin/env bash
# Release provenance contract: every release carries its SLSA provenance as a
# release asset, and only the job that signs it can request an OIDC token.
#
# OpenSSF Scorecard's Signed-Releases check reads the assets of the latest
# releases, not the repository's attestations page. It scores a release 10 when
# an asset ends in `.intoto.jsonl`, 8 for a bare signature file and 0 for
# neither. The build job already produced attestations that `gh attestation
# verify` accepts, but none of them was uploaded, so v0.27.0 scored 0. This test
# pins the path from the attest step to the published asset, because a break
# anywhere on it is silent: the release still succeeds and Scorecard sees nothing.
#
# Host-side only: parses .github/workflows/release.yml and the docs, no network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

python3 - "$repo_root" <<'PYTHON'
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("release-provenance: PyYAML is required")

root = Path(sys.argv[1])
failures = []


def fail(message):
    failures.append(message)


def read(rel):
    try:
        return (root / rel).read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {rel}: {error}")
        return ""


workflow = yaml.safe_load(read(".github/workflows/release.yml")) or {}
jobs = workflow.get("jobs", {})
build = jobs.get("build", {})
release = jobs.get("release", {})
if not build or not release:
    fail("release.yml must define the build and release jobs")
build_steps = build.get("steps", [])
release_steps = release.get("steps", [])


def index_of(steps, predicate):
    for index, step in enumerate(steps):
        if isinstance(step, dict) and predicate(step):
            return index
    return -1


# --- the provenance step ------------------------------------------------------

PIN = re.compile(r"actions/attest-build-provenance@[0-9a-f]{40}")
provenance_at = index_of(build_steps, lambda s: PIN.fullmatch(str(s.get("uses", ""))) is not None)
if provenance_at < 0:
    fail("build job has no step using actions/attest-build-provenance pinned by a full commit SHA")
    provenance = {}
else:
    provenance = build_steps[provenance_at]
# Exactly one provenance attestation: a second one for the same subjects is noise
# that `gh attestation verify` would have to sort through.
provenance_steps = [
    s for s in build_steps
    if isinstance(s, dict)
    and re.match(r"actions/attest(?:-build-provenance)?@", str(s.get("uses", "")))
    and "sbom-path" not in (s.get("with") or {})
    and "predicate-type" not in (s.get("with") or {})
]
if len(provenance_steps) != 1:
    fail(f"build job must make exactly one provenance attestation, found {len(provenance_steps)}")
provenance_id = provenance.get("id", "")
if not provenance_id:
    fail("the provenance step needs an id so its bundle-path output can be read")
subjects = str((provenance.get("with") or {}).get("subject-path", ""))
for binary in ("sysknife-${{ github.ref_name }}-linux-${{ matrix.arch }}",
               "sysknife-daemon-${{ github.ref_name }}-linux-${{ matrix.arch }}"):
    if binary not in [line.strip() for line in subjects.splitlines()]:
        fail(f"provenance subject-path does not name {binary}")

# --- staging the bundle as `*.intoto.jsonl` -----------------------------------

stage_at = index_of(build_steps, lambda s: ".intoto.jsonl" in str(s.get("run", "")))
if stage_at < 0:
    fail("no build step stages the bundle under a *.intoto.jsonl name")
else:
    stage = build_steps[stage_at]
    script = str(stage.get("run", ""))
    env_text = " ".join(str(v) for v in (stage.get("env") or {}).values())
    if f"steps.{provenance_id}.outputs.bundle-path" not in env_text + script:
        fail("the staging step does not read the provenance step's bundle-path output")
    if not re.search(r"\.intoto\.jsonl", script) or "linux-${ARCH}" not in script:
        fail("the staged bundle must be named sysknife-${VERSION}-linux-${ARCH}.intoto.jsonl")
    if not re.search(r"test\s+-s\b|\[\s+-s\b|\[\[\s+-s\b", script):
        fail("the staging step must fail when the bundle is missing or empty")
    if provenance_at >= 0 and stage_at < provenance_at:
        fail("the bundle is staged before the provenance step produced it")
    upload_at = index_of(build_steps, lambda s: str(s.get("uses", "")).startswith("actions/upload-artifact@"))
    if upload_at < 0:
        fail("build job has no upload-artifact step")
    else:
        if stage_at > upload_at:
            fail("the bundle is staged after the artifact upload, so it never reaches the release job")
        if ".intoto.jsonl" not in str((build_steps[upload_at].get("with") or {}).get("path", "")):
            fail("upload-artifact does not carry the *.intoto.jsonl bundle to the release job")

# --- the release job uploads it -----------------------------------------------

upload = next((str(s.get("run", "")) for s in release_steps
               if isinstance(s, dict) and 'gh release upload "$VERSION"' in str(s.get("run", ""))), "")
if not upload:
    fail("release job has no `gh release upload` step")
for arch in ("x86_64", "aarch64"):
    if f'"dist/sysknife-${{VERSION}}-linux-{arch}.intoto.jsonl"' not in upload:
        fail(f"gh release upload does not publish the {arch} *.intoto.jsonl bundle")

# --- permissions: signing stays confined to the jobs that sign -----------------

top = workflow.get("permissions", {})
if any(level != "read" for level in (top or {}).values()):
    fail(f"workflow-level permissions must be read-only, found {top}")
holders = {name for name, job in jobs.items()
           if isinstance(job, dict) and (job.get("permissions") or {}).get("attestations") == "write"}
if holders != {"build"}:
    fail(f"attestations: write must belong to the build job alone, found {sorted(holders)}")
tokens = {name for name, job in jobs.items()
          if isinstance(job, dict) and (job.get("permissions") or {}).get("id-token") == "write"}
if tokens != {"build", "publish-npm", "publish-registry"}:
    fail(f"id-token: write belongs to build, publish-npm and publish-registry only, found {sorted(tokens)}")
if release.get("permissions") != {"contents": "write"}:
    fail(f"the release job must hold contents: write and nothing else, found {release.get('permissions')}")

# --- the docs tell a user how to verify it -------------------------------------

release_doc = read("docs/release.md")
readme = read("README.md")
for label, text in (("docs/release.md", release_doc), ("README.md", readme)):
    if "gh attestation verify" not in text:
        fail(f"{label} does not document `gh attestation verify`")
    if "--repo lacs-project/sysknife" not in text:
        fail(f"{label} does not pin the verification to --repo lacs-project/sysknife")
# A command, not prose that happens to mention the flag: `gh attestation verify`
# with its continuation lines, ending in --bundle <file>.intoto.jsonl.
# One bundle covers sysknife and sysknife-daemon, so both must be shown.
bundle_commands = re.findall(
    r"gh attestation verify[^\n]*\\\n(?:[^\n]*\\\n)*[^\n]*--bundle\s+\S+\.intoto\.jsonl", release_doc)
if len(bundle_commands) < 2:
    fail(f"docs/release.md must show `gh attestation verify ... --bundle <file>.intoto.jsonl` for both "
         f"binaries, found {len(bundle_commands)}")

if failures:
    print("release-provenance: FAIL", file=sys.stderr)
    for message in failures:
        print(f"  - {message}", file=sys.stderr)
    sys.exit(1)
print("Release provenance contract passed.")
PYTHON
