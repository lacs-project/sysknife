"""Exercise the shipped gates with local action metadata in a fixture tree."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from github_yaml import discover  # noqa: E402

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


class ActionMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workflows = self.root / ".github/workflows"
        self.actions = self.root / ".github/actions"
        self.workflows.mkdir(parents=True)
        self.templates = self.root / ".github/ISSUE_TEMPLATE"
        self.templates.mkdir()
        (self.templates / "bug.yml").write_text(
            "---\nname: Bug report\ndescription: Report a bug\nbody: []\n", encoding="utf-8")
        (self.workflows / "ci.yml").write_text(
            "---\njobs:\n  build:\n    steps:\n"
            f"      - uses: actions/checkout@{SHA}  # v7.0.1\n"
            '        with:\n          node-version: "24"\n', encoding="utf-8")

    def action(self, text, suffix="yml"):
        path = self.actions / "nested/setup" / f"action.{suffix}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def run_command(self, command, expected=None):
        result = subprocess.run(command, capture_output=True, text=True)
        output = result.stdout + result.stderr
        if expected is None:
            self.assertEqual(result.returncode, 0, output)
        else:
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn(expected, output)
        return output

    def pins(self, expected=None):
        source = (ROOT / "tests/release/release-rehearsal.test.sh").read_text()
        function = source.split("assert_action_pins() {", 1)[1].split(
            '\nassert_action_pins "${repo_root}', 1)[0]
        script = 'repo_root="$1"\nassert_action_pins() {' + function
        script += '\nassert_action_pins "$2" 1 "$3"\n'
        return self.run_command(["bash", "-c", script, "fixture", str(ROOT),
                                 str(self.workflows), str(self.actions)], expected)

    def test_absent_actions_and_pinned_nested_yaml(self):
        self.assertEqual(len(discover(self.workflows, self.actions)), 1)
        self.pins()
        for suffix in ("yml", "yaml"):
            path = self.action("---\nname: setup\nruns:\n  using: composite\n  steps:\n"
                               f"    - uses: actions/checkout@{SHA}  # v7.0.1\n", suffix)
            self.assertIn(path, discover(self.workflows, self.actions))
        self.assertIn("Checked 3 uses:", self.pins())
        output = self.run_command([sys.executable, str(ROOT / "scripts/action-pin-comments.py"),
                                   str(self.root)])
        self.assertIn(".github/actions/nested/setup/action.yaml", output)
        self.assertIn(".github/actions/nested/setup/action.yml", output)

    def test_unpinned_composite_cannot_hide_behind_workflow_floor(self):
        for body in ("runs: {using: composite, steps: [{uses: attacker/exfil@main}]}\n",
                     "runs:\n  using: composite\n  steps:\n    - uses: attacker/exfil@main\n"):
            self.action(body)
            self.pins("action is not pinned")
            self.run_command([sys.executable, str(ROOT / "scripts/action-pin-comments.py"),
                              str(self.root)], "cannot check non-SHA reference")

    def test_empty_actions_is_not_a_successful_scan(self):
        self.actions.mkdir()
        self.pins("no action metadata files matched")

    def test_empty_workflows_is_not_rescued_by_action(self):
        (self.workflows / "ci.yml").unlink()
        self.action("runs: {using: composite, steps: []}\n")
        self.pins("no workflow files matched")

    def test_empty_templates_is_not_rescued_by_workflow(self):
        (self.templates / "bug.yml").unlink()
        command = ["bash", str(ROOT / "scripts/lint-github-yaml.sh"), str(self.root)]
        for unrelated in (False, True):
            with self.subTest(unrelated_file=unrelated):
                if unrelated:
                    (self.templates / "README.md").write_text("Not a YAML template.\n")
                with self.assertRaisesRegex(ValueError, "no issue templates matched"):
                    discover(self.workflows, self.actions, self.templates)
                self.run_command(command, "no issue templates matched")

    def test_malformed_and_directory_metadata_fail(self):
        path = self.action("runs: [\n")
        self.pins("cannot parse")
        path.unlink()
        path.mkdir()
        self.pins("Is a directory")

    def test_bad_composite_shape_fails(self):
        self.action("runs: {using: composite, steps: invalid}\n")
        self.pins("steps must be a sequence")

    def test_node_eol_follows_actions(self):
        node_gate = str(ROOT / "tests/release/node-eol.test.sh")
        self.action('runs:\n  using: composite\n  steps:\n    - with:\n        node-version: "18"\n')
        self.run_command(["bash", node_gate, str(self.root)], "pins Node 18")
        self.action("runs:\n  using: node18\n  main: index.js\n")
        self.run_command(["bash", node_gate, str(self.root)], "pins Node 18")
        self.action("runs:\n  using: node24\n  main: index.js\n")
        self.run_command(["bash", node_gate, str(self.root)])

    def test_yaml_lint_follows_actions(self):
        self.action("---\nname: setup\nruns:\n  using: composite\n  steps: []\n")
        command = ["bash", str(ROOT / "scripts/lint-github-yaml.sh"), str(self.root)]
        self.run_command(command)
        self.action("---\nruns: [\n")
        self.run_command(command, "syntax error")


if __name__ == "__main__":
    unittest.main()
