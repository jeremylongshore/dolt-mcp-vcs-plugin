"""Hermetic reaper behavior: real Bash functions, fake MCP and process effects.

No test starts Dolt, connects to a database, enumerates host processes, or sends
signals. Pinned formatter contract: dolthub/dolt-mcp v0.3.6,
mcp/pkg/db/database.go (rowMapToMarkdown).
"""
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/dolt-idle-reaper.sh"
SPEC = importlib.util.spec_from_file_location("reaper_endpoint", ROOT / "scripts/reaper_endpoint.py")
ENDPOINT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENDPOINT)

FAKE_CLIENT = '''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
p = Path(os.environ["FIXTURE"])
cfg = json.loads((p / "config.json").read_text())
with (p / "calls.jsonl").open("a") as f:
    f.write(json.dumps(args) + "\\n")
if args[-1] == "list_databases":
    output, status = cfg["list"], cfg.get("list_status", 0)
elif args[-1] == "SELECT HEX(SCHEMA_NAME) AS database_hex FROM information_schema.SCHEMATA":
    output, status = cfg["discovery"], cfg.get("discovery_status", 0)
else:
    db = args[args.index("--database") + 1]
    output = cfg.get("queries", {}).get(db, "dirty\\n---\\n0")
    status = cfg.get("query_status", 0)
print(output)
sys.exit(status)
'''


class ReaperBehavior(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / "go/bin").mkdir(parents=True)
        executable = self.base / "go/bin/dolt-mcp-server"
        executable.write_text("#!/bin/sh\nexit 99\n")
        executable.chmod(0o755)
        self.workspace = self.base / "workspace"
        (self.workspace / ".beads/dolt").mkdir(parents=True)
        (self.workspace / ".beads/dolt-server.pid").write_text("424242\n")
        self.client = self.base / "client.py"
        self.client.write_text(FAKE_CLIENT)
        self.env = dict(os.environ, HOME=str(self.base), FIXTURE=str(self.base),
                        BEADS_DOLT_MCP_CLIENT=str(self.client),
                        PATH=f"{self.base}/go/bin:" + os.environ["PATH"],
                        DOLT_HOST="remote.invalid", DOLT_PORT="9999",
                        DOLT_FLAVOR="doltgres", DOLT_DATABASE="other", DOLT_BRANCH="other",
                        IDLE_MIN="90")

    def config(self, **kwargs):
        cfg = {"list": "Database\n---\ndolt\nproject"}
        cfg.update(kwargs)
        cfg.setdefault("discovery", "database_hex\n---\n" + "\n".join(
            name.encode().hex().upper() for name in cfg["list"].splitlines()[2:]))
        (self.base / "config.json").write_text(json.dumps(cfg))
        (self.base / "calls.jsonl").write_text("")

    def run_bash(self, body):
        return subprocess.run(["bash", "-c", 'source "$1"\n' + body, "test", str(SCRIPT)],
                              env=self.env, capture_output=True, text=True, timeout=10, check=False)

    def check(self, port="3307"):
        return self.run_bash('MCP_CLIENT="$BEADS_DOLT_MCP_CLIENT"\nworking_set_clean ' + port)

    def calls(self):
        return [json.loads(line) for line in (self.base / "calls.jsonl").read_text().splitlines()]

    def test_dirty_dolt_with_clean_project_refused(self):
        self.config(queries={"dolt": "dirty\n---\n1"})
        self.assertNotEqual(self.check().returncode, 0)
        self.assertEqual(self.calls()[-1][self.calls()[-1].index("--database") + 1], "dolt")

    def test_only_clean_dolt_allowed(self):
        self.config(list="Database\n---\ndolt")
        self.assertEqual(self.check().returncode, 0)

    def test_every_database_checked_and_environment_cannot_redirect(self):
        self.config(list="Database\n---\ninformation_schema\nmysql\nperformance_schema\nsys\ndolt\nproject")
        self.assertEqual(self.check().returncode, 0)
        calls = self.calls()
        self.assertEqual(len(calls), 4)
        for args in calls:
            for flag, expected in [("--host", "127.0.0.1"), ("--port", "3307"),
                                   ("--flavor", "dolt"), ("--branch", "main")]:
                self.assertEqual(args[args.index(flag) + 1], expected)
        self.assertEqual(calls[0][calls[0].index("--database") + 1], "information_schema")

    def test_dirty_later_database_refused(self):
        self.config(queries={"project": "dirty\n---\n7"})
        self.assertNotEqual(self.check().returncode, 0)
        self.assertEqual(len(self.calls()), 4)

    def test_malformed_counts_refused(self):
        for output in ["", "0", "dirty\n---\n0junk", "dirty\n---\n0\n1", "dirty\n---\n-0",
                       "dirty\n---\n00", "dirty\n---\n 0", "wrong\n---\n0", "dirty\n---\n0\nerror"]:
            with self.subTest(output=output):
                self.config(queries={"dolt": output})
                self.assertNotEqual(self.check().returncode, 0)

    def test_query_failure_with_clean_output_refused(self):
        self.config(query_status=4)
        self.assertNotEqual(self.check().returncode, 0)

    def test_database_list_failure_with_valid_output_refused(self):
        self.config(list_status=4)
        self.assertNotEqual(self.check().returncode, 0)
        self.assertEqual(len(self.calls()), 1)

    def test_empty_system_only_and_malformed_lists_refused(self):
        for output in ["", "Database\n---", "Database\n---\ninformation_schema", "dolt",
                       "wrong\n---\ndolt", "Database\nwrong\ndolt",
                       "Database\n---\ndolt\n\nproject", "Database\n---\nodd | name",
                       "Database\n---\n---"]:
            with self.subTest(output=output):
                self.config(list=output)
                self.assertNotEqual(self.check().returncode, 0)

    def test_encoded_discovery_passes_existing_read_only_main_gate(self):
        spec = importlib.util.spec_from_file_location("sql_classifier", ROOT / "scripts/sql_classifier.py")
        classifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(classifier)
        sql = re.search(r'"(SELECT HEX[^"\n]+)"', SCRIPT.read_text()).group(1)
        allowed, _, reason = classifier.gate_decision(
            sql, allow_mutation=False, branch="main", maturity="ga")
        self.assertTrue(allowed, reason)

    def test_encoded_newline_database_cannot_hide_behind_clean_list_rows(self):
        names = ["clean1", "clean2", "clean1\nclean2"]
        self.config(list="Database\n---\nclean1\nclean2\nclean1\nclean2",
                    discovery="database_hex\n---\n" + "\n".join(
                        name.encode().hex().upper() for name in names))
        self.assertNotEqual(self.check().returncode, 0)
        # Only the connection hint and encoded discovery ran; no clean-count
        # query can make the malformed authoritative inventory acceptable.
        self.assertEqual(len(self.calls()), 2)
        self.assertIn("HEX(SCHEMA_NAME)", self.calls()[-1][-1])

    def test_authoritative_inventory_includes_database_missing_from_hint(self):
        self.config(list="Database\n---\nproject",
                    discovery="database_hex\n---\n70726F6A656374\n646F6C74",
                    queries={"dolt": "dirty\n---\n1"})
        self.assertNotEqual(self.check().returncode, 0)
        self.assertEqual(self.calls()[-1][self.calls()[-1].index("--database") + 1], "dolt")

    def test_failed_encoded_discovery_is_refused_before_counts(self):
        self.config(discovery_status=4)
        self.assertNotEqual(self.check().returncode, 0)
        self.assertEqual(len(self.calls()), 2)

    def test_empty_system_only_malformed_or_unsupported_encoded_inventory_refused(self):
        for output in ["", "database_hex\n---", "Database\n---\n646F6C74",
                       "database_hex\nwrong\n646F6C74", "database_hex\n---\n0",
                       "database_hex\n---\nGG", "database_hex\n---\n646f6c74",
                       "database_hex\n---\n646F6C7400", "database_hex\n---\nFF",
                       "database_hex\n---\n646F6C74\n\n70726F6A656374",
                       "database_hex\n---\n646F6C74\n646F6C74",
                       "database_hex\n---\n" + b"information_schema".hex().upper()]:
            with self.subTest(output=output):
                self.config(discovery=output)
                self.assertNotEqual(self.check().returncode, 0)
                self.assertEqual(len(self.calls()), 2)

    def test_invalid_port_and_missing_client_refused(self):
        self.config()
        for port in ['""', "0", "65536", "oops", "-1"]:
            with self.subTest(port=port):
                self.assertNotEqual(self.check(port).returncode, 0)
        self.client.unlink()
        self.assertNotEqual(self.check().returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_invalid_idle_thresholds_fail_before_process_discovery(self):
        for threshold in ("0", "-1", "oops", "1+1", "1000000"):
            with self.subTest(threshold=threshold):
                self.env["IDLE_MIN"] = threshold
                result = self.run_bash('pgrep() { echo UNEXPECTED; }\nmain')
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("UNEXPECTED", result.stdout)

    def test_unknown_options_fail_before_process_discovery(self):
        for options in ("--dryrun", "--dry-run extra", "--help"):
            with self.subTest(options=options):
                result = self.run_bash('pgrep() { echo UNEXPECTED; }\nmain ' + options)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("UNEXPECTED", result.stdout)

    def test_source_only_has_no_lock_or_process_side_effects(self):
        result = self.run_bash("true")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertFalse((self.base / ".local/state/dolt-reaper").exists())

    def loop(self, activity=1000, identity="100 3307", change="", dry=False):
        # Source only defines functions. Every access to candidate processes and
        # every signal are replaced before main is invoked; never call the real
        # reaper executable against the host, including in --dry-run mode.
        body = r'''
pgrep() { echo 424242; }
readlink() {
  if [[ "$1" == /proc/424242/cwd ]]; then echo "$HOME/workspace";
  else command readlink "$@"; fi
}
date() { if [[ "$1" == +%s ]]; then echo 10000; else command date "$@"; fi; }
latest_activity() {
  if [[ "$CHANGE" == activity && -s "$FIXTURE/calls.jsonl" ]]; then echo 10000;
  elif [[ "$CHANGE" == removed && -s "$FIXTURE/calls.jsonl" ]]; then echo 0;
  else echo "$ACTIVITY"; fi
}
mtime() { echo "$ACTIVITY"; }
server_identity() {
  if [[ "$CHANGE" == identity && -s "$FIXTURE/calls.jsonl" ]]; then echo '101 3307';
  elif [[ "$CHANGE" == port && -s "$FIXTURE/calls.jsonl" ]]; then echo '100 3308';
  elif [[ "$CHANGE" == vanished && -s "$FIXTURE/calls.jsonl" ]]; then return 1;
  else [[ -n "$IDENTITY" ]] && echo "$IDENTITY"; fi
}
kill() { printf '%s\n' "$*" >> "$FIXTURE/signals"; }
main ''' + ("--dry-run" if dry else "")
        self.env.update(ACTIVITY=str(activity), IDENTITY=identity, CHANGE=change)
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stderr)
        signal = self.base / "signals"
        return result.stdout, signal.read_text() if signal.exists() else ""

    def test_idle_non_beads_process_is_never_queried_or_signaled(self):
        self.config()
        (self.workspace / ".beads/dolt-server.pid").unlink()
        out, signals = self.loop()
        self.assertIn("1 kept", out)
        self.assertEqual(signals, "")
        self.assertEqual(self.calls(), [])

    def test_beads_directory_with_other_pid_does_not_claim_unrelated_server(self):
        self.config()
        (self.workspace / ".beads/dolt-server.pid").write_text("424243\n")
        out, signals = self.loop()
        self.assertIn("1 kept", out)
        self.assertEqual(signals, "")
        self.assertEqual(self.calls(), [])

    def test_existing_beads_data_cwd_is_owned_but_arbitrary_cwd_is_not(self):
        for relative in (".beads", ".beads/dolt"):
            with self.subTest(relative=relative):
                self.env["CANDIDATE_CWD"] = str(self.workspace / relative)
                result = self.run_bash('bd_workspace 424242 "$CANDIDATE_CWD"')
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout.strip(), str(self.workspace))
        for cwd in (self.base / "missing/.beads/dolt", self.workspace / "freshie/dolt"):
            with self.subTest(cwd=cwd):
                self.env["CANDIDATE_CWD"] = str(cwd)
                result = self.run_bash('bd_workspace 424242 "$CANDIDATE_CWD"')
                self.assertNotEqual(result.returncode, 0)

    def test_active_process_is_kept_without_query(self):
        self.config()
        out, signals = self.loop(activity=9999)
        self.assertIn("1 kept", out)
        self.assertEqual(signals, "")
        self.assertEqual(self.calls(), [])

    def test_idle_clean_process_receives_only_term(self):
        self.config()
        out, signals = self.loop()
        self.assertIn("1 reaped", out)
        self.assertEqual(signals, "-TERM 424242\n")

    def test_idle_dirty_process_never_signaled(self):
        self.config(queries={"dolt": "dirty\n---\n1"})
        out, signals = self.loop()
        self.assertIn("1 skipped-dirty", out)
        self.assertEqual(signals, "")

    def test_dry_run_never_signals(self):
        self.config()
        out, signals = self.loop(dry=True)
        self.assertIn("WOULD REAP", out)
        self.assertEqual(signals, "")

    def test_unknown_endpoint_keeps_process_without_query(self):
        self.config()
        out, signals = self.loop(identity="")
        self.assertIn("1 skipped-dirty", out)
        self.assertEqual(signals, "")
        self.assertEqual(self.calls(), [])

    def test_changed_activity_or_identity_after_query_preserves_process(self):
        for change in ("activity", "removed", "identity", "port", "vanished"):
            with self.subTest(change=change):
                self.config()
                out, signals = self.loop(change=change)
                self.assertIn("1 kept", out)
                self.assertEqual(signals, "")


class EndpointIdentity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.proc = Path(self.temp.name)
        self.process = self.proc / "42"
        for name in ("42/ns", "42/fd", "42/net", "self/ns"):
            (self.proc / name).mkdir(parents=True)
        (self.process / "ns/net").symlink_to("net:[100]")
        (self.proc / "self/ns/net").symlink_to("net:[100]")
        (self.process / "fd/3").symlink_to("socket:[123]")
        (self.process / "cmdline").write_bytes(b"/bin/dolt\x00sql-server\x00-P\x009999\x00")
        (self.process / "stat").write_text("42 (dolt) " + " ".join(["S"] + ["0"] * 18 + ["100"]))
        self.tcp()

    def tcp(self, rows=None):
        if rows is None:
            rows = ["0: 0100007F:0CEB 00000000:0000 0A 0:0 0:0 0 0 0 123"]
        (self.process / "net/tcp").write_text("header\n" + "\n".join(rows) + "\n")

    def test_actual_owned_port_beats_declared_port(self):
        self.assertEqual(ENDPOINT.identity(42, self.proc), "100 3307")

    def test_wildcard_listener_allowed(self):
        self.tcp(["0: 00000000:0CEB 00000000:0000 0A 0:0 0:0 0 0 0 123"])
        self.assertEqual(ENDPOINT.identity(42, self.proc), "100 3307")

    def test_missing_unowned_nonlistening_nonlocal_ambiguous_malformed_refused(self):
        row = "0: 0100007F:0CEB 00000000:0000 0A 0:0 0:0 0 0 0 123"
        for rows in [[], [row.replace("123", "999")], [row.replace("0A", "01")],
                     [row.replace("0100007F", "0200007F")], ["malformed"],
                     [row, row.replace("0CEB", "0CEC")]]:
            with self.subTest(rows=rows):
                self.tcp(rows)
                with self.assertRaises(ValueError):
                    ENDPOINT.identity(42, self.proc)

    def test_different_namespace_refused(self):
        (self.process / "ns/net").unlink()
        (self.process / "ns/net").symlink_to("net:[101]")
        with self.assertRaises(ValueError):
            ENDPOINT.identity(42, self.proc)

    def test_wrapper_process_not_treated_as_dolt(self):
        for args in [b"bash\x00-c\x00dolt sql-server\x00", b"dolt\x00version\x00"]:
            with self.subTest(args=args):
                (self.process / "cmdline").write_bytes(args)
                with self.assertRaises(ValueError):
                    ENDPOINT.identity(42, self.proc)

    def test_missing_process_refused(self):
        with self.assertRaises(OSError):
            ENDPOINT.identity(999, self.proc)


if __name__ == "__main__":
    unittest.main()
