#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/scripts" "$fixture/docs"
cp "$repo_root/scripts/markdown-link-files.sh" "$fixture/scripts/"
cat > "$fixture/scripts/markdown-link-exclusions.txt" <<'EOF'
# One deliberately excluded fixture document.
docs/skipped.md
EOF
cat > "$fixture/scripts/markdown-link-external-files.txt" <<'EOF'
README.md
EOF
touch "$fixture/README.md" "$fixture/docs/guide.md" "$fixture/docs/skipped.md"

git -C "$fixture" init -q
git -C "$fixture" add README.md docs scripts/markdown-link-exclusions.txt \
    scripts/markdown-link-external-files.txt

files=()
while IFS= read -r -d '' file; do
    files+=("$file")
done < <("$fixture/scripts/markdown-link-files.sh")
expected=(README.md docs/guide.md)
[[ "${files[*]}" == "${expected[*]}" ]] || {
    printf 'markdown-link-files: expected <%s>, got <%s>\n' \
        "${expected[*]}" "${files[*]}" >&2
    exit 1
}

external_files=()
while IFS= read -r -d '' file; do
    external_files+=("$file")
done < <("$fixture/scripts/markdown-link-files.sh" --external)
[[ "${external_files[*]}" == 'README.md' ]] || {
    printf 'markdown-link-files: expected external set <README.md>, got <%s>\n' \
        "${external_files[*]}" >&2
    exit 1
}

printf 'docs/missing.md\n' > "$fixture/scripts/markdown-link-external-files.txt"
if output="$("$fixture/scripts/markdown-link-files.sh" --external 2>&1)"; then
    printf 'markdown-link-files: stale external-check path unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'external-check path is not a tracked Markdown file: docs/missing.md' \
    <<< "$output" || {
    printf 'markdown-link-files: stale external-check error omitted its path: %s\n' \
        "$output" >&2
    exit 1
}

printf 'docs/missing.md\n' >> "$fixture/scripts/markdown-link-exclusions.txt"
if output="$("$fixture/scripts/markdown-link-files.sh" 2>&1)"; then
    printf 'markdown-link-files: stale exclusion unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'excluded path is not a tracked Markdown file: docs/missing.md' <<< "$output" || {
    printf 'markdown-link-files: stale exclusion error omitted its path: %s\n' "$output" >&2
    exit 1
}

# Remove exclusions so a failed enumeration reaches git ls-files itself.
: > "$fixture/scripts/markdown-link-exclusions.txt"
mv "$fixture/.git" "$fixture/git-backup"
if output="$("$fixture/scripts/markdown-link-files.sh" 2>&1)"; then
    printf 'markdown-link-files: failed git enumeration unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'failed to enumerate tracked Markdown files' <<< "$output"
mv "$fixture/git-backup" "$fixture/.git"

git -C "$fixture" rm --cached -q -- '*.md'
if output="$("$fixture/scripts/markdown-link-files.sh" 2>&1)"; then
    printf 'markdown-link-files: empty derived set unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'no tracked Markdown files to check' <<< "$output"

# Exercise the real consumer bodies with an offline checker and producer.
python3 - "$repo_root" "$fixture" <<'PYTEST'
import os
from pathlib import Path
import re
import subprocess
import sys

root, fixture = map(Path, sys.argv[1:])
local = (root / "scripts/ci-local.sh").read_text()
body = re.search(r"hygiene_markdown_link_check\(\) \(\n(.*?)\n\)", local, re.S).group(1)
workflow = (root / ".github/workflows/ci.yml").read_text()
bodies = {"local": body}
for kind in ("internal", "external"):
    match = re.search(r"      - name: Check " + kind + r" markdown links\n        run: \|\n(.*?)(?=\n      - name:)", workflow, re.S)
    bodies[kind] = "\n".join(line[10:] for line in match.group(1).splitlines())
bin_dir = fixture / "bin"
bin_dir.mkdir()
checker = bin_dir / "markdown-link-check"
checker.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "${@: -1}" >> "$CHECK_LOG"\n')
checker.chmod(0o755)
env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], CHECK_LOG=str(fixture / "checked"))
producer = fixture / "scripts/markdown-link-files.sh"
for scenario, script in {
    "failed": "exit 1",
    "empty": "exit 0",
    "partial failure": "printf 'README.md\\0'; exit 1",
    "valid": "printf 'README.md\\0docs/a guide.md\\0'",
}.items():
    producer.write_text("#!/usr/bin/env bash\n" + script + "\n")
    for name, body in bodies.items():
        log = fixture / "checked"
        log.unlink(missing_ok=True)
        # ci-local.sh enables strict mode; the workflow uses GitHub's default bash -e.
        shell = ["bash", "-euo", "pipefail"] if name == "local" else ["bash", "-e"]
        result = subprocess.run([*shell, "-c", 'repo_root="$1"\n' + body, "consumer", str(fixture)], cwd=fixture, env=env, capture_output=True, text=True)
        if scenario != "valid":
            assert result.returncode != 0, f"{name} consumer accepted {scenario} producer"
        else:
            assert result.returncode == 0, (name, result.stderr)
            expected = ["README.md", "docs/a guide.md"] * (2 if name == "local" else 1)
            assert log.read_text().splitlines() == expected, f"{name} consumer did not check every file"
PYTEST

printf 'markdown-link-files: derived files and exclusions validated.\n'
