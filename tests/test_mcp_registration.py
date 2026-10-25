"""Exercise the installed MCP declaration against an inert, isolated wire peer."""
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DESTRUCTIVE = (
    "drop_database", "dolt_reset_hard", "dolt_push_branch", "dolt_pull_branch",
    "merge_dolt_branch", "merge_dolt_branch_no_fast_forward", "delete_dolt_branch",
)
FAKE = r'''
import json, os, sys
from pathlib import Path
receipt = Path(os.environ["FAKE_RECEIPT"])
with receipt.open("a") as out:
    out.write(json.dumps({"argv": sys.argv[1:], "password": os.environ.get("DOLT_PASSWORD")}) + "\n")
for line in sys.stdin:
    msg = json.loads(line)
    with receipt.open("a") as out:
        out.write(json.dumps(msg) + "\n")
    if msg.get("id") is None:
        continue
    if msg["method"] == "tools/list":
        result = {"tools": [{"name": n} for n in ["query", "exec", "list_databases", "drop_database", "dolt_reset_hard", "dolt_push_branch", "dolt_pull_branch", "merge_dolt_branch", "merge_dolt_branch_no_fast_forward", "delete_dolt_branch"]]}
    else:
        result = {"content": [{"type": "text", "text": "EXECUTED"}]}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
'''


class InstalledRegistration(unittest.TestCase):
    def exercise(self, opt_in=False):
        with tempfile.TemporaryDirectory(prefix="dolt installed plugin ") as tmp:
            base = Path(tmp)
            plugin = base / "plugin with spaces"
            (plugin / "scripts").mkdir(parents=True)
            for name in ("dolt-mcp-guard.py", "sql_classifier.py"):
                shutil.copyfile(ROOT / "scripts" / name, plugin / "scripts" / name)
            shutil.copyfile(ROOT / ".mcp.json", plugin / ".mcp.json")
            bin_dir = base / "bin"
            bin_dir.mkdir()
            (bin_dir / "python3").symlink_to(sys.executable)
            fake = bin_dir / "dolt-mcp-server"
            fake.write_text("#!" + sys.executable + "\n" + FAKE)
            fake.chmod(0o755)
            home = base / "home"
            home.mkdir()
            receipt = base / "receipt.jsonl"
            # Allowlist, rather than inherit, the environment: no real credentials,
            # DB endpoints, Python startup hooks, or real executables on PATH.
            env = {"PATH": str(bin_dir), "HOME": str(home), "FAKE_RECEIPT": str(receipt),
                   "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
            if opt_in:
                env["DOLT_MCP_ALLOW_MUTATION"] = "1"
            server = json.loads((plugin / ".mcp.json").read_text())["mcpServers"]["dolt-mcp-vcs"]
            defaults = {"${DOLT_HOST:-127.0.0.1}": "fixture.invalid", "${DOLT_PORT:-3308}": "1",
                        "${DOLT_USER:-root}": "fixture-user", "${DOLT_DATABASE:-beads}": "fixture-db",
                        "${DOLT_PASSWORD:-}": "synthetic-password"}
            def expand(value):
                return defaults.get(value, value.replace("${CLAUDE_PLUGIN_ROOT}", str(plugin)))
            env.update({key: expand(value) for key, value in server.get("env", {}).items()})
            command = [expand(server["command"]), *map(expand, server["args"])]
            proc = subprocess.Popen(command, cwd=home, env=env, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ)
            received = []
            def request(method, params=None):
                ident = len(received) + 1
                msg = {"jsonrpc": "2.0", "id": ident, "method": method, "params": params or {}}
                proc.stdin.write(json.dumps(msg) + "\n")
                proc.stdin.flush()
                self.assertTrue(selector.select(5), "launcher did not answer within timeout")
                response = json.loads(proc.stdout.readline())
                self.assertEqual(response["id"], ident)
                received.append(response)
                return response["result"]
            try:
                probe = request("tools/call", {"name": "drop_database", "arguments": {}})
                self.assertTrue(probe.get("isError"), "destructive call reached inert peer: " + repr(probe))
                tools = request("tools/list")["tools"]
                self.assertEqual({t["name"] for t in tools}, {"query", "exec", "list_databases"})
                for name in DESTRUCTIVE:
                    self.assertTrue(request("tools/call", {"name": name, "arguments": {}}).get("isError"), name)
                for name, args in (("exec", {"query": "DROP DATABASE fixture"}),
                                   ("query", {"query": "DELETE FROM t"}), ("exec", {})):
                    self.assertTrue(request("tools/call", {"name": name, "arguments": args}).get("isError"))
                for name in ("query", "exec"):
                    for sql in ("PREPARE p FROM 'DELETE FROM t'", "EXECUTE p",
                                "EXPLAIN (ANALYZE, BUFFERS) DELETE FROM t"):
                        with self.subTest(tool=name, sql=sql, opt_in=opt_in):
                            result = request("tools/call", {"name": name,
                                             "arguments": {"query": sql}})
                            self.assertTrue(result.get("isError"), result)
                write = request("tools/call", {"name": "exec", "arguments": {"query": "INSERT INTO t VALUES (1)"}})
                self.assertEqual(bool(write.get("isError")), not opt_in)
                read = request("tools/call", {"name": "query", "arguments": {"query": "SELECT 1"}})
                self.assertEqual(read["content"][0]["text"], "EXECUTED")
                proc.stdin.close()
                self.assertEqual(proc.wait(timeout=5), 0)
                rows = [json.loads(line) for line in receipt.read_text().splitlines()]
                self.assertEqual(rows[0], {"argv": ["--stdio", "--dolt", "--host", "fixture.invalid", "--port", "1", "--user", "fixture-user", "--database", "fixture-db"], "password": "synthetic-password"})
                calls = [r for r in rows[1:] if r["method"] == "tools/call"]
                self.assertEqual(len(calls), 2 if opt_in else 1)
                self.assertEqual([r["params"]["name"] for r in calls], ["exec", "query"] if opt_in else ["query"])
            finally:
                selector.close()
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    stream.close()

    def test_default_registration_refuses_mutations(self):
        self.exercise()

    def test_opt_in_never_enables_destructive_calls(self):
        self.exercise(opt_in=True)


if __name__ == "__main__":
    unittest.main()
