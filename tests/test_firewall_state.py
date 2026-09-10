"""Fixture tests for the read-only firewall reporter; no host probes run."""
import importlib.machinery
import importlib.util
import json
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
