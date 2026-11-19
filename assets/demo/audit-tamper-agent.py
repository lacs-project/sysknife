#!/usr/bin/env python3
"""Stand-in for an MCP client (Claude Code, Cursor, Codex CLI) in the audit-tamper demo.

It speaks MCP over stdio to the real `sysknife mcp-server`, so the planner call, the
daemon previews, the approval receipts and the signed audit rows are all the real
ones. Only the chat window is missing. For every plan step whose risk is in the
allowed set it fetches a receipt from `sysknife approve`, the human-run command, and
executes with it. Every other step stays previewed and unapproved, which is what an
operator who says no leaves behind.

usage: audit-tamper-agent.py RISKS INTENT [INTENT ...]    e.g.  low "check disk space"
"""
import json
import re
import subprocess
import sys
import time


class Mcp:
    def __init__(self):
        self.proc = subprocess.Popen(
            ["sysknife", "mcp-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=sys.stderr, text=True)
        self.next_id = 0
        self.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                "clientInfo": {"name": "overnight-agent", "version": "1"}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def send(self, message):
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def rpc(self, method, params):
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise SystemExit("sysknife mcp-server closed its output")
            reply = json.loads(line)
            if reply.get("id") == self.next_id:
                return reply

    def tool(self, name, arguments):
        reply = self.rpc("tools/call", {"name": name, "arguments": arguments})
        if "error" in reply:
            raise SystemExit(f"{name}: {reply['error']}")
        result = reply["result"]
        if result.get("isError"):
            raise SystemExit(f"{name}: {result['content'][0]['text'][:300]}")
        if "structuredContent" in result:
            return result["structuredContent"]
        return json.loads(result["content"][0]["text"])


def receipt_for(transaction_id):
    """`sysknife approve` refuses to run without a terminal, so give it one with script(1)."""
    out = subprocess.run(
        ["script", "-qec", f"sysknife approve {transaction_id}", "/dev/null"],
        input="y\n", capture_output=True, text=True, check=False).stdout.replace("\r", "")
    found = re.search(r"Approval receipt: (\S+)", out)
    if not found:
        raise SystemExit(f"no approval receipt for {transaction_id}")
    return found.group(1)


def main():
    allowed = set(sys.argv[1].split(","))
    mcp = Mcp()
    for intent in sys.argv[2:]:
        plan = mcp.tool("sysknife_plan", {"intent": intent})
        approved = []
        for step in plan["steps"]:
            print(f"  plan  {step['action_name']:<20} {step['risk_level']:<7} "
                  f"{step['transaction_id'][:8]}", flush=True)
            if step["risk_level"] in allowed:
                approved.append({"transaction_id": step["transaction_id"],
                                 "action_name": step["action_name"], "params": step["params"],
                                 "approval_receipt": receipt_for(step["transaction_id"])})
        if approved:
            for result in mcp.tool("sysknife_execute", {"steps": approved})["steps"]:
                print(f"  exec  {result['action_name']:<20} {result['status']}", flush=True)
        time.sleep(3)   # stay under per-minute provider token limits


main()
