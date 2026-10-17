#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
import re
import sys
from pathlib import Path

import yaml

workflow = yaml.safe_load(Path(".github/workflows/release.yml").read_text())
steps = workflow["jobs"]["release"]["steps"]
scripts = [step.get("run", "") for step in steps]
creates = [script for script in scripts if 'gh release create "$VERSION"' in script]
if len(creates) != 1:
    sys.exit("FAIL: expected exactly one release creation script")

# Match the control flow, not merely the presence of view and create somewhere
# in the workflow. Creation must be confined to the explicit not-found branch.
guard = re.fullmatch(
    r'if release_output="\$\(gh release view "\$VERSION" --repo "\$REPO" 2>&1\)"; then\n'
    r'(?P<exists>.*?)'
    r'^elif \[\[ "\$release_output" == \*\'release not found\'\* \]\]; then\n'
    r'(?P<missing>.*?)'
    r'^else\n(?P<error>.*?)^fi\s*',
    creates[0],
    re.MULTILINE | re.DOTALL,
)
if guard is None:
    sys.exit("FAIL: gh release create is not guarded by the release-existence check")

create = re.fullmatch(
    r'\s*gh release create "\$VERSION" \\\n'
    r'\s*--repo "\$REPO" \\\n'
    r'\s*--title "\$VERSION" \\\n'
    r'\s*--generate-notes\s*',
    guard["missing"],
)
if create is None or 'gh release create' in guard["exists"] + guard["error"]:
    sys.exit("FAIL: release creation must occur only for a missing release")
if not re.fullmatch(r'\s*echo [^\n]+\n', guard["exists"]):
    sys.exit("FAIL: an existing release must continue without creation or exit")
if not re.fullmatch(
    r"\s*printf '::error::[^\n]+\"\$release_output\" >&2\n\s*exit 1\n",
    guard["error"],
):
    sys.exit("FAIL: unexpected lookup errors must be reported and stop the release")

create_index = scripts.index(creates[0])
if not any('gh release upload "$VERSION"' in script and '--clobber' in script
           for script in scripts[create_index + 1:]):
    sys.exit("FAIL: guarded creation must be followed by clobber-enabled upload")

print("release creation re-run contract passed.")
PY
