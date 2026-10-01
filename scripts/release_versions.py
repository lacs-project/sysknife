#!/usr/bin/env python3
"""Read and write every place the release version lives.

The places themselves are declared in release-versions.json at the repository
root, so `scripts/check_release_versions.sh` and `scripts/bump_version.sh` work
from one list instead of each keeping its own. A manifest that is not in that
file is invisible to both, which is what
`tests/release/version-sites.test.sh` exists to catch.

Subcommands:
  values          every declared version value, one per line, for the checker
  sites           every file the registry accounts for, one per line
  bump <version>  write <version> everywhere, refusing on anything unexpected
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
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
    if not found:
        die("no version sites resolved; refusing to report success over nothing")
    return found


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


def cmd_values(cfg: dict) -> None:
    for _, value in all_values(cfg):
        print(value)


def cmd_pincount(cfg: dict) -> None:
    n = sum(len(internal_pins(cfg, rel)) for rel in cfg["cargo_manifests"])
    if n == 0:
        die("no internal dependency pins found; the registry's manifests are stale")
    print(n)


def cmd_sites(cfg: dict) -> None:
    seen = list(cfg["cargo_manifests"])
    seen += [s["file"] for s in cfg["json_sites"]]
    seen += list(cfg["generated_lockfiles"])
    for rel in seen:
        print(rel)


def cmd_bump(cfg: dict, target: str, when: str | None) -> None:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", target):
        die(f"{target} is not MAJOR.MINOR.PATCH; release.yml's tag pattern "
            "takes no prerelease suffix, and a pushed tag cannot be moved")

    current = package_version(cfg, cfg["cargo_manifests"][0])
    if current == target:
        print(f"already at {target}; nothing to write")
        return
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
        # reviewable, then check structurally that nothing else moved. A
        # dependency pinned at the same version as ours is the collateral
        # damage this catches.
        text = text.replace(f'"{current}"', f'"{target}"')
        after = json.loads(text)
        declared = {tuple(path) for path in (tuple(x) for x in site["paths"])}
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

    disagree = [(w, v) for w, v in all_values(cfg) if v != target]
    if disagree:
        die(f"after writing, these still disagree: {disagree}")
    print(f"{written} version field(s) written")


def main() -> None:
    argv = sys.argv[1:]
    if not argv:
        die("need a subcommand: values, sites, or bump <version>")
    cfg = load_config()
    cmd = argv[0]
    if cmd == "values":
        cmd_values(cfg)
    elif cmd == "pincount":
        cmd_pincount(cfg)
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
