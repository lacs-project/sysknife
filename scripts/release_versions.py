#!/usr/bin/env python3
"""Read and write every place the release version lives.

The places themselves are declared in release-versions.json at the repository
root, so `scripts/check_release_versions.sh` and `scripts/bump_version.sh` work
from one list instead of each keeping its own. A manifest that is not in that
file is invisible to both, which is what
`tests/release/version-sites.test.sh` exists to catch.

Subcommands:
  check [version] validates every declared release version, lockfile member and changelog heading
  values          every declared version value, one per line
  sites           every file the registry accounts for, one per line
  bump <version>  write <version> everywhere, refusing on anything unexpected
"""
from __future__ import annotations

import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "release-versions.json"


def die(msg: str) -> "NoReturn":  # noqa: F821
    print(f"release_versions: {msg}", file=sys.stderr)
    raise SystemExit(1)


def load_config() -> dict:
    if not CONFIG.exists():
        die(f"no {CONFIG}; the version registry is missing")
    cfg = json.loads(CONFIG.read_text())
    for key in ("cargo_manifests", "json_sites", "internal_dep_prefix",
                "generated_lockfiles", "changelog", "unreleased_heading"):
        if key not in cfg:
            die(f"release-versions.json has no {key!r}")
    # A registry that declares nothing would make every caller report success
    # over an empty set, which is the failure mode this file is built against.
    if not cfg["cargo_manifests"]:
        die("release-versions.json lists no cargo manifests")
    if not cfg["json_sites"]:
        die("release-versions.json lists no JSON sites")
    return cfg


def resolve(doc, path, where: str):
    """Follow a declared JSON path, naming the file when it does not exist."""
    cur = doc
    for step in path:
        try:
            cur = cur[step]
        except (KeyError, IndexError, TypeError):
            die(f"{where}: no such path {path}; the registry is stale")
    if not isinstance(cur, str):
        die(f"{where}: path {path} holds {type(cur).__name__}, not a version string")
    return cur


def package_version(cfg: dict, rel: str) -> str:
    m = re.search(r'^version = "([^"]+)"', (ROOT / rel).read_text(), re.M)
    if not m:
        die(f"{rel}: no [package] version")
    return m.group(1)


def package_name(cfg: dict, rel: str) -> str:
    text = (ROOT / rel).read_text()
    package = re.search(r'^\[package\]\s*(.*?)(?=^\[|\Z)', text, re.M | re.S)
    name = package and re.search(r'^name\s*=\s*"([^"]+)"', package.group(1), re.M)
    if not name:
        die(f"{rel}: no [package] name")
    return name.group(1)


def internal_pins(cfg: dict, rel: str) -> list[tuple[str, str]]:
    """Every `sysknife-x = { path = .., version = ".." }` pin in one manifest.

    crates.io resolves this field at publish time, so a bump that misses one
    publishes a crate depending on the previous release rather than the tree
    that was just built, and nothing notices until somebody builds against the
    published crate.
    """
    prefix = re.escape(cfg["internal_dep_prefix"])
    out = []
    for m in re.finditer(rf'^({prefix}[a-z-]+)\s*=\s*\{{([^}}\n]*)\}}',
                         (ROOT / rel).read_text(), re.M):
        v = re.search(r'version\s*=\s*"([^"]+)"', m.group(2))
        if not v:
            die(f"{rel}: internal dependency {m.group(1)} is "
                "missing an explicit version pin")
        out.append((m.group(1), v.group(1)))
    return out


def all_values(cfg: dict) -> list[tuple[str, str]]:
    """(where, value) for every declared site, in a stable order."""
    found: list[tuple[str, str]] = []
    for rel in cfg["cargo_manifests"]:
        found.append((f"{rel} [package]", package_version(cfg, rel)))
        for name, ver in internal_pins(cfg, rel):
            found.append((f"{rel} pin {name}", ver))
    for site in cfg["json_sites"]:
        rel = site["file"]
        doc = json.loads((ROOT / rel).read_text())
        for path in site["paths"]:
            found.append((f"{rel} {'.'.join(str(p) for p in path)}",
                          resolve(doc, path, rel)))
    members = {package_name(cfg, rel): package_version(cfg, rel)
               for rel in cfg["cargo_manifests"]}
    for rel in cfg["generated_lockfiles"]:
        text = (ROOT / rel).read_text()
        lock_members: dict[str, str] = {}
        for block in re.finditer(r'^\[\[package\]\]\s*\n(.*?)(?=^\[\[package\]\]\s*$|\Z)',
                                 text, re.M | re.S):
            body = block.group(1)
            name = re.search(r'^name\s*=\s*"([^"]+)"$', body, re.M)
            version = re.search(r'^version\s*=\s*"([^"]+)"$', body, re.M)
            source = re.search(r'^source\s*=', body, re.M)
            if name and version and not source and name.group(1) in members:
                lock_members[name.group(1)] = version.group(1)
        for name, expected in members.items():
            actual = lock_members.get(name)
            if actual is None:
                die(f"{rel}: workspace package {name} has no lockfile entry")
            found.append((f"{rel} workspace member {name}", actual))
    found.append((f"{cfg['changelog']} latest release heading",
                  changelog_version(cfg)))
    if not found:
        die("no version sites resolved; refusing to report success over nothing")
    return found


def changelog_version(cfg: dict) -> str:
    rel = cfg["changelog"]
    text = (ROOT / rel).read_text()
    head = cfg["unreleased_heading"]
    if text.count(head) != 1:
        die(f"{rel}: expected exactly one {head!r}")
    body = text.split(head, 1)[1]
    match = re.search(r'^## \[([0-9]+\.[0-9]+\.[0-9]+)\]', body, re.M)
    if not match:
        die(f"{rel}: no release heading follows {head}")
    return match.group(1)


def validated_values(cfg: dict, expected: str | None = None) -> tuple[list[tuple[str, str]], str]:
    found = all_values(cfg)
    baseline = found[0][1]
    disagree = [(where, value) for where, value in found if value != baseline]
    if disagree:
        details = "; ".join(f"{where} holds {value}" for where, value in disagree)
        die(f"release versions are inconsistent: expected {baseline}; {details}")
    if expected and baseline != expected:
        die(f"Release tag version {expected} does not match package version {baseline}")
    return found, baseline


def leaves(doc, prefix=()):
    """Every scalar in a document, keyed by path, for a structural diff."""
    if isinstance(doc, dict):
        for k, v in doc.items():
            yield from leaves(v, prefix + (k,))
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            yield from leaves(v, prefix + (i,))
    else:
        yield prefix, doc


def replace_declared(text: str, before, current: str, target: str, declared: set) -> str:
    """Rewrite each `"current"` in `text` whose JSON leaf is a declared path."""
    needle, replacement = f'"{current}"', f'"{target}"'
    keep = []
    for match in re.finditer(re.escape(needle), text):
        start = match.start()
        trial = json.loads(text[:start] + replacement + text[start + len(needle):])
        moved = {k for (k, a), (_, b) in zip(leaves(before), leaves(trial)) if a != b}
        if moved and moved <= declared:
            keep.append(start)
    for start in reversed(keep):
        text = text[:start] + replacement + text[start + len(needle):]
    return text


def cmd_values(cfg: dict) -> None:
    for _, value in all_values(cfg):
        print(value)


def cmd_check(cfg: dict, expected: str | None) -> None:
    _, version = validated_values(cfg, expected)
    pin_count = sum(len(internal_pins(cfg, rel)) for rel in cfg["cargo_manifests"])
    if pin_count == 0:
        die("no internal dependency pins found; the registry's manifests are stale")
    print(f"All release versions match {version} ({pin_count} internal dependency pins checked).")


def cmd_sites(cfg: dict) -> None:
    seen = list(cfg["cargo_manifests"])
    seen += [s["file"] for s in cfg["json_sites"]]
    seen += list(cfg["generated_lockfiles"])
    seen.append(cfg["changelog"])
    for rel in seen:
        print(rel)


def release_files(cfg: dict) -> list[str]:
    files = list(cfg["cargo_manifests"])
    files += [site["file"] for site in cfg["json_sites"]]
    files += list(cfg["generated_lockfiles"])
    files.append(cfg["changelog"])
    return list(dict.fromkeys(files))


def copy_tracked_files(destination: Path) -> None:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True
    )
    if result.returncode:
        detail = os.fsdecode(result.stderr).strip()
        die(f"git ls-files failed while staging a release bump: {detail}")
    paths = result.stdout.split(b"\0")
    if not any(paths):
        die("git ls-files returned no tracked paths; cannot stage a release bump")
    for raw_path in paths:
        if not raw_path:
            continue
        rel = Path(os.fsdecode(raw_path))
        source = ROOT / rel
        if not source.exists() and not source.is_symlink():
            continue
        staged = destination / rel
        staged.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            staged.symlink_to(os.readlink(source))
        elif source.is_file():
            shutil.copy2(source, staged)


def install_staged_files(cfg: dict, staged_root: Path, temp_root: Path) -> None:
    files = release_files(cfg)
    backups = temp_root / "originals"
    for rel in files:
        source = staged_root / rel
        destination = ROOT / rel
        if not source.is_file() or not destination.is_file():
            die(f"{rel}: staged release file or destination is missing")
        backup = backups / rel
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(destination, backup)

    replaced: list[str] = []
    try:
        for rel in files:
            os.replace(staged_root / rel, ROOT / rel)
            replaced.append(rel)
    except OSError as error:
        restore_errors = []
        for rel in reversed(replaced):
            try:
                os.replace(backups / rel, ROOT / rel)
            except OSError as restore_error:
                restore_errors.append(f"{rel}: {restore_error}")
        if restore_errors:
            die(f"could not install staged release files ({error}); rollback failed: "
                + "; ".join(restore_errors))
        die(f"could not install staged release files; original files were restored: {error}")


def cmd_bump(cfg: dict, target: str, when: str | None) -> None:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", target):
        die(f"{target} is not MAJOR.MINOR.PATCH; release.yml's tag pattern "
            "takes no prerelease suffix, and a pushed tag cannot be moved")

    _, current = validated_values(cfg)
    if current == target:
        print(f"already at {target}; nothing to write")
        return

    try:
        with tempfile.TemporaryDirectory(prefix=".release-version-bump-", dir=ROOT.parent) as temp:
            temp_root = Path(temp)
            staged_root = temp_root / ROOT.name
            staged_root.mkdir()
            copy_tracked_files(staged_root)
            staged = runpy.run_path(str(staged_root / "scripts" / "release_versions.py"))
            staged_cfg = staged["load_config"]()
            staged["cmd_bump_in_place"](staged_cfg, target, when)
            install_staged_files(cfg, staged_root, temp_root)
    except (OSError, shutil.Error) as error:
        die(f"could not prepare staged release version files: {error}")


def cmd_bump_in_place(cfg: dict, target: str, when: str | None) -> None:
    current = package_version(cfg, cfg["cargo_manifests"][0])
    print(f"{current} -> {target}")
    prefix = cfg["internal_dep_prefix"]
    written = 0

    for rel in cfg["cargo_manifests"]:
        p = ROOT / rel
        text = p.read_text()
        text, n_pkg = re.subn(rf'^version = "{re.escape(current)}"',
                              f'version = "{target}"', text, flags=re.M)
        if n_pkg != 1:
            die(f"{rel}: expected 1 [package] version at {current}, found {n_pkg}")
        text, n_pin = re.subn(
            rf'({re.escape(prefix)}[a-z-]+\s*=\s*\{{[^}}\n]*version\s*=\s*)"{re.escape(current)}"',
            rf'\g<1>"{target}"', text)
        p.write_text(text)
        written += n_pkg + n_pin
        print(f"  {rel}: 1 package version, {n_pin} internal pin(s)")
        for name, ver in internal_pins(cfg, rel):
            if ver != target:
                die(f"{rel}: pin {name} is still {ver} after the write")

    for site in cfg["json_sites"]:
        rel = site["file"]
        p = ROOT / rel
        text = p.read_text()
        before = json.loads(text)
        for path in site["paths"]:
            got = resolve(before, path, rel)
            if got != current:
                die(f"{rel}: path {path} holds {got}, not {current}; "
                    "the registry and the tree disagree")
        # Replace the text rather than re-serialising, so the diff stays
        # reviewable. Only an occurrence that lands on a declared path is
        # replaced: npm's `scheduler` sat at 0.28.0 in the GUI lockfile when
        # SysKnife did, and rewriting every "0.28.0" string made the next bump
        # refuse itself. The structural check below still catches anything
        # else that moved.
        declared = {tuple(path) for path in (tuple(x) for x in site["paths"])}
        text = replace_declared(text, before, current, target, declared)
        after = json.loads(text)
        moved = {k for (k, a), (_, b) in zip(leaves(before), leaves(after)) if a != b}
        stray = sorted(moved - declared)
        if stray:
            die(f"{rel}: {stray} also changed and is not a declared version site")
        missed = sorted(declared - moved)
        if missed:
            die(f"{rel}: declared site(s) {missed} did not change")
        p.write_text(text)
        written += len(site["paths"])
        print(f"  {rel}: {len(site['paths'])} path(s)")

    for lock in cfg["generated_lockfiles"]:
        p = ROOT / lock
        before = p.read_text()
        r = subprocess.run(["cargo", "metadata", "--offline", "--format-version", "1"],
                           cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if r.returncode != 0:
            die(f"cargo could not refresh {lock}: "
                f"{r.stderr.decode(errors='replace').strip()}")
        after = p.read_text()
        moved = set()
        for blk in re.finditer(r'^\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"',
                               after, re.M):
            name, ver = blk.group(1), blk.group(2)
            if ver == target and f'name = "{name}"\nversion = "{current}"' in before:
                moved.add(name)
        strangers = sorted(n for n in moved if not n.startswith(prefix))
        if strangers:
            die(f"{lock}: {strangers} moved to {target} and are not workspace members")
        if not moved:
            die(f"{lock}: cargo moved no workspace member to {target}")
        print(f"  {lock}: {len(moved)} workspace member(s), refreshed by cargo")

    ch = ROOT / cfg["changelog"]
    text = ch.read_text()
    head = cfg["unreleased_heading"]
    if text.count(head) != 1:
        die(f"{cfg['changelog']}: expected exactly one {head!r}")
    body = text.split(head, 1)[1]
    nxt = re.search(r'^## \[', body, re.M)
    if body[: nxt.start() if nxt else len(body)].strip() == "":
        die(f"{cfg['changelog']}: {head} is empty, so this release has no notes")
    # Reuse whatever separator the previous entry used instead of hardcoding
    # one, so this cannot drift from the file's own style.
    prev = re.search(r'^## \[[0-9][^\]]*\](\s*\S\s*)\d{4}-\d{2}-\d{2}\s*$', text, re.M)
    sep = prev.group(1) if prev else " - "
    stamp = when or date.today().isoformat()
    ch.write_text(text.replace(head, f"{head}\n\n## [{target}]{sep}{stamp}", 1))
    print(f"  {cfg['changelog']}: rolled to [{target}]{sep}{stamp}")

    validated_values(cfg, target)
    print(f"{written} version field(s) written")


def main() -> None:
    argv = sys.argv[1:]
    if not argv:
        die("need a subcommand: values, sites, or bump <version>")
    cfg = load_config()
    cmd = argv[0]
    if cmd == "values":
        cmd_values(cfg)
    elif cmd == "check":
        expected = argv[1].lstrip("v") if len(argv) > 1 else None
        cmd_check(cfg, expected)
    elif cmd == "sites":
        cmd_sites(cfg)
    elif cmd == "bump":
        if len(argv) < 2:
            die("bump needs a version")
        when = argv[3] if len(argv) > 3 and argv[2] == "--date" else None
        cmd_bump(cfg, argv[1].lstrip("v"), when)
    else:
        die(f"unknown subcommand {cmd!r}")


if __name__ == "__main__":
    main()
