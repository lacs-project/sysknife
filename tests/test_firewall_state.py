"""Fixture tests for the read-only firewall reporter; no host probes run."""
import importlib.machinery
import importlib.util
import json
import re
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / "packaging/sysknife-firewall-state"
loader = importlib.machinery.SourceFileLoader("firewall_state", str(path))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


def probe(stdout="", status="ok"):
    return {"status": status, "stdout": stdout, "stderr": ""}


def nft(entries):
    return probe(json.dumps({"nftables": entries}))


class FirewallStateTests(unittest.TestCase):
    def test_large_ruleset_keeps_summary_and_caveat_before_bounded_probes(self):
        entries = [{"chain": {"hook": "forward", "policy": "drop"}}]
        entries += [{"rule": {"comment": "forward rule " + "x" * 200}} for _ in range(120)]
        original = nft(entries)
        result = module.summarize(original, probe("Status: inactive"), probe(status="failed"))
        payload = json.dumps(result)
        self.assertLess(payload.index('"note"'), payload.index('"probes"'))
        self.assertEqual(result["nftables"]["rule_count"], 120)
        self.assertIn("nftables", result["backends_observed"])
        self.assertIn("[truncated by firewall-state]", result["probes"]["nftables"]["stdout"])
        self.assertEqual(json.loads(original["stdout"])["nftables"], entries)
        self.assert_payload_survives_brain_cap(payload)

    def assert_payload_survives_brain_cap(self, payload):
        # Read the shipped cap so a future reduction cannot silently invalidate
        # the helper's wire budget. The entire JSON must fit, not just its note.
        source = (path.parents[1] / "crates/sysknife-brain/src/sanitize.rs").read_text(encoding="utf-8")
        match = re.search(r"pub const MAX_OUTPUT_BYTES: usize = (\d+) \* (\d+);", source)
        self.assertIsNotNone(match)
        cap = int(match[1]) * int(match[2])
        encoded = payload.encode("utf-8")
        self.assertLessEqual(len(encoded), cap)
        survived = json.loads(encoded[:cap])
        self.assertIn("Empty/failed probes do not prove", survived["note"])

    def test_all_probe_streams_are_bounded_after_json_escaping(self):
        for text in ['"\\\n\t' * 5000, "防火墙😀" * 5000]:
            with self.subTest(text=text[:8]):
                p = {"status": "failed", "stdout": text, "stderr": text, "returncode": 1}
                result = module.summarize(p, p, p)
                self.assertEqual(result["state"], "unknown")
                for observation in result["probes"].values():
                    self.assertEqual(observation["returncode"], 1)
                    for field in ("stdout", "stderr"):
                        self.assertIn("[truncated by firewall-state]", observation[field])
                self.assert_payload_survives_brain_cap(json.dumps(result))

    def test_small_probe_streams_are_preserved_without_a_marker(self):
        p = {"status": "failed", "stdout": "a\\b\n中文", "stderr": "permission denied", "returncode": 1}
        result = module.summarize(p, p, p)
        self.assertEqual(result["probes"], {"nftables": p, "ufw": p, "firewalld": p})

    def test_nft_rules_are_visible_when_ufw_is_inactive(self):
        result = module.summarize(nft([
            {"chain": {"hook": "input", "policy": "drop"}},
            {"rule": {"expr": [{"accept": None}]}}
        ]), probe("Status: inactive"), probe(status="failed"))
        self.assertEqual(result["nftables"]["status"], "rules_present")
        self.assertIn("nftables", result["backends_observed"])
        self.assertNotIn("ufw", result["backends_observed"])

    def test_active_ufw_and_nft_are_not_exclusive(self):
        result = module.summarize(nft([{"chain": {"hook": "input", "policy": "drop"}}]), probe("Status: active\nTo Action From"), probe(status="failed"))
        self.assertEqual(result["backends_observed"], ["ufw", "nftables"])

    def test_neither_never_claims_the_host_is_unfiltered(self):
        result = module.summarize(nft([]), probe("Status: inactive"), probe(status="failed"))
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["backends_observed"], [])

    def test_unavailable_permission_denied_and_malformed_are_unknown(self):
        for p in [probe(status="unavailable"), probe(status="failed"), probe(status="timeout"), probe("not json"), probe('{}'), probe('{"nftables":{}}')]:
            result = module.summarize(p, probe("Status: inactive"), probe(status="failed"))
            self.assertEqual(result["state"], "unknown")
            self.assertNotEqual(result["nftables"]["status"], "no_rules_observed")

    def test_unhooked_rules_and_empty_tables_do_not_prove_filtering(self):
        for entries in [[{"table": {"name": "filter"}}], [{"chain": {"name": "unused"}}, {"rule": {"expr": [{"drop": None}]}}]]:
            result = module.summarize(nft(entries), probe(status="unavailable"), probe(status="unavailable"))
            self.assertEqual(result["state"], "unknown")

    def test_firewalld_output_is_preserved(self):
        result = module.summarize(nft([]), probe("Status: inactive"), probe("public (active)\n  services: ssh"))
        self.assertIn("firewalld", result["backends_observed"])
        self.assertIn("services: ssh", result["probes"]["firewalld"]["stdout"])


if __name__ == "__main__":
    unittest.main()
