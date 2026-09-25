"""Unit suite for the universal flavor/mode detector (dolt-detect.py).

Run:  python3 -m unittest tests.test_dolt_detect -v
Pure functions only — no dolt binary, no live servers, no network. Fixtures
cover: dir-layout classification (classic / server-store / embedded / MIXED /
negative), metadata.json interpretation, wire version-string parsing (incl. the
doltgres-contains-dolt and dumbo cases), the ephemeral-port-over-config case
(/proc table beats the declared -P flag), DoltLite/SQLite header sniffing, and
findings -> descriptor assembly (mode field, file: endpoints, maturity map).
The descriptor composition seam (mode/file: refusal in descriptor-to-mcp-args)
is covered here too so the contract can't drift apart silently.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

_SCRIPTS = os.path.join(os.path.dirname(__file__), os.pardir, "scripts")


def _load(name, fname):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_SCRIPTS, fname))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dd = _load("dolt_detect", "dolt-detect.py")
dta = _load("descriptor_to_mcp_args", "descriptor-to-mcp-args.py")


class TestHeaderSniff(unittest.TestCase):
    def test_doltlite_magic(self):
        # dolthub/doltlite chunk_store.h CHUNK_STORE_MAGIC 0x444C5443, written
        # little-endian by CS_WRITE_U32 -> on-disk first bytes are b"CTLD".
        self.assertEqual(dd.sniff_header(b"CTLD" + b"\x01\x00\x00\x00rest"), "doltlite")

    def test_plain_sqlite_is_not_doltlite(self):
        self.assertEqual(dd.sniff_header(b"SQLite format 3\x00" + b"x" * 16), "sqlite")

    def test_garbage_and_short_reads(self):
        self.assertIsNone(dd.sniff_header(b"MZ\x90\x00"))
        self.assertIsNone(dd.sniff_header(b""))
        self.assertIsNone(dd.sniff_header(b"CT"))  # truncated magic


class TestLayoutClassification(unittest.TestCase):
    def test_classic_repo_at_root(self):
        (f,) = dd.classify_dolt_dirs([""])
        self.assertEqual((f["flavor"], f["mode"]), ("dolt", "repo"))

    def test_nested_classic_repo_sidecar(self):
        # the sqlite-runtime + dolt-system-of-record sidecar (freshie/dolt/freshie)
        (f,) = dd.classify_dolt_dirs(["freshie/dolt/freshie"])
        self.assertEqual((f["flavor"], f["mode"], f["database"]),
                         ("dolt", "repo", "freshie"))

    def test_server_mode_store(self):
        (f,) = dd.classify_dolt_dirs([".beads/dolt/OPS"])
        self.assertEqual((f["mode"], f["database"], f.get("live")),
                         ("server", "OPS", False))

    def test_embedded_store(self):
        (f,) = dd.classify_dolt_dirs([".beads/embeddeddolt/spine"])
        self.assertEqual((f["mode"], f["database"]), ("embedded", "spine"))

    def test_mixed_layout_returns_both_ranked(self):
        # migrated workspace: BOTH layouts present -> BOTH findings, and after
        # ranking the (potential) server store outranks the embedded one.
        fs = dd.classify_dolt_dirs([".beads/dolt/bb", ".beads/embeddeddolt/bb"])
        self.assertEqual(len(fs), 2)
        ranked = dd.rank_findings(fs)
        self.assertEqual([f["mode"] for f in ranked], ["server", "embedded"])

    def test_negative(self):
        self.assertEqual(dd.classify_dolt_dirs([]), [])

    def test_data_dir_root_marker_is_not_a_database(self):
        # bd's data-dir root (.beads/dolt) carries its own .dolt marker; only its
        # CHILDREN are databases — the root must never become a finding.
        fs = dd.classify_dolt_dirs([".beads/dolt", ".beads/dolt/qmd_team_intent_kb",
                                    ".beads/embeddeddolt"])
        self.assertEqual([(f["mode"], f["database"]) for f in fs],
                         [("server", "qmd_team_intent_kb")])


class TestMetadataInterpretation(unittest.TestCase):
    def test_embedded_marker(self):
        f = dd.interpret_metadata({"dolt_mode": "embedded", "dolt_database": "spine"})
        self.assertEqual((f["flavor"], f["mode"], f["database"]),
                         ("dolt", "embedded", "spine"))

    def test_server_marker_is_not_claimed_live(self):
        f = dd.interpret_metadata({"dolt_mode": "server", "dolt_database": "beads"})
        self.assertEqual(f["mode"], "server")
        self.assertFalse(f["live"])

    def test_non_marker(self):
        self.assertIsNone(dd.interpret_metadata({"something": "else"}))
        self.assertIsNone(dd.interpret_metadata(None))


class TestWireParsing(unittest.TestCase):
    def _greeting(self, version):
        body = b"\x0a" + version.encode() + b"\x00" + b"\x01\x00\x00\x00salt"
        return len(body).to_bytes(3, "little") + b"\x00" + body

    def test_mysql_greeting_version_extracted(self):
        self.assertEqual(dd.parse_mysql_greeting(self._greeting("8.0.33-Dolt")),
                         "8.0.33-Dolt")

    def test_greeting_garbage(self):
        self.assertIsNone(dd.parse_mysql_greeting(b"HTTP/1.1 400 Bad Request"))
        self.assertIsNone(dd.parse_mysql_greeting(b""))

    def test_flavor_from_version_all_makes_and_models(self):
        self.assertEqual(dd.flavor_from_version("8.0.33-Dolt"), "dolt")
        self.assertEqual(dd.flavor_from_version("PostgreSQL 15.2 (Doltgres 1.0)"),
                         "doltgres")  # 'doltgres' must win over its 'dolt' substring
        self.assertEqual(dd.flavor_from_version("DumboDB 0.1-pre (dolt storage)"),
                         "dumbo")     # 'dumbo' must win over 'dolt'
        self.assertIsNone(dd.flavor_from_version("8.0.36 MySQL Community Server"))
        self.assertIsNone(dd.flavor_from_version(""))


class TestProcessParsing(unittest.TestCase):
    TCP_FIXTURE = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
        "retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:9A29 00000000:0000 0A 00000000:00000000 00:00000000 "
        "00000000  1000        0 424242 1 0000000000000000 100 0 0 10 0\n"
        "   1: 0100007F:0CEC 00000000:0000 01 00000000:00000000 00:00000000 "
        "00000000  1000        0 424243 1 0000000000000000 100 0 0 10 0\n"
    )

    def test_declared_port_parsed(self):
        self.assertEqual(dd.port_from_cmdline("dolt sql-server -P 3308 --host 127.0.0.1"), 3308)
        self.assertEqual(dd.port_from_cmdline("dolt sql-server --port 41000"), 41000)
        self.assertIsNone(dd.port_from_cmdline("dolt sql-server"))

    def test_actual_bound_port_beats_declared(self):
        # THE estate gotcha: config.yaml/-P says 3306 (0x0CEC) but that socket is
        # not LISTEN; the actually-bound LISTEN port is 39465 (0x9A29). The
        # detector must return the /proc truth, never the declared value.
        ports = dd.parse_tcp_listen_ports(self.TCP_FIXTURE, ["424242", "424243"])
        self.assertEqual(ports, [0x9A29])
        declared = dd.port_from_cmdline("dolt sql-server -P 3306")
        self.assertNotIn(declared, ports)

    def test_inode_filter(self):
        self.assertEqual(dd.parse_tcp_listen_ports(self.TCP_FIXTURE, ["999999"]), [])

    def test_server_store_matching(self):
        self.assertTrue(dd.match_server_to_store("/w/.beads/dolt/OPS", "/w/.beads/dolt"))
        self.assertTrue(dd.match_server_to_store("/w/.beads/dolt/OPS",
                                                 "/w/.beads/dolt/OPS"))
        self.assertFalse(dd.match_server_to_store("/w/.beads/dolt/OPS", "/other/place"))
        self.assertFalse(dd.match_server_to_store("", "/w"))


class TestDescriptorAssembly(unittest.TestCase):
    def test_live_server_descriptor_composes_downstream(self):
        f = {"flavor": "dolt", "mode": "server", "live": True,
             "host": "127.0.0.1", "port": 39465, "database": "beads"}
        d = dd.assemble_descriptor(f)
        self.assertEqual(d["endpoint"], "127.0.0.1:39465")
        self.assertEqual(d["mode"], "server")
        self.assertEqual(d["maturity"], "ga")
        self.assertEqual(dta.validate(d), [])          # validator accepts it
        out = dta.transform(d)                          # and it transforms
        self.assertIn("--dolt", out["args"])
        self.assertIn("39465", out["args"])

    def test_doltgres_descriptor_transforms_to_doltgres_flag(self):
        f = {"flavor": "doltgres", "mode": "server", "live": True,
             "host": "127.0.0.1", "port": 5432, "database": "app"}
        d = dd.assemble_descriptor(f)
        self.assertEqual(d["maturity"], "beta")
        self.assertIn("--doltgres", dta.transform(d)["args"])

    def test_embedded_descriptor_is_refused_by_wire_transform(self):
        f = {"flavor": "dolt", "mode": "embedded", "database": "spine",
             "path": ".beads/embeddeddolt/spine"}
        d = dd.assemble_descriptor(f, "/w")
        self.assertTrue(d["endpoint"].startswith("file:/w/"))
        self.assertEqual(dta.validate(d), [])           # valid descriptor...
        with self.assertRaises(ValueError):             # ...but never a wire conn
            dta.transform(d)

    def test_doltlite_descriptor_stays_fail_closed(self):
        f = {"flavor": "doltlite", "mode": "file", "database": "inventory",
             "path": "/w/inventory.db"}
        d = dd.assemble_descriptor(f)
        self.assertEqual(d["maturity"], "alpha")
        self.assertEqual(dta.validate(d), [])
        with self.assertRaises(ValueError):             # decision-6 stub holds
            dta.transform(d)

    def test_unknown_mode_rejected_by_validator(self):
        d = {"flavor": "dolt", "mode": "warp-drive", "endpoint": "h:1",
             "database": "x", "creds-ref": "env:X", "maturity": "ga"}
        self.assertTrue(any("mode" in e for e in dta.validate(d)))


class TestEndToEndOnFixtureTree(unittest.TestCase):
    """detect() against a real (temp) directory tree — filesystem wrappers only,
    still no processes/network (--no-processes path)."""

    def _make_tree(self, spec):
        root = tempfile.mkdtemp(prefix="dolt-detect-test-")
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", root], check=False))
        for rel, content in spec.items():
            p = os.path.join(root, rel)
            if content is None:
                os.makedirs(p, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                mode = "wb" if isinstance(content, bytes) else "w"
                with open(p, mode) as fh:
                    fh.write(content)
        return root

    def test_mixed_workspace_plus_metadata(self):
        root = self._make_tree({
            ".beads/dolt/bb/.dolt": None,
            ".beads/embeddeddolt/bb/.dolt": None,
            ".beads/metadata.json": json.dumps(
                {"dolt_mode": "embedded", "dolt_database": "bb"}),
        })
        findings, _ = dd.detect(root, with_processes=False)
        self.assertEqual([f["mode"] for f in findings], ["server", "embedded"])
        self.assertIn("metadata.json", findings[1]["evidence"])

    def test_doltlite_file_and_sqlite_sidecar_pairing(self):
        root = self._make_tree({
            "inventory.sqlite": b"SQLite format 3\x00" + b"\x00" * 32,
            "versioned.db": b"CTLD" + b"\x01\x00\x00\x00" + b"\x00" * 32,
            "dolt/freshie/.dolt": None,
        })
        findings, sqlite_paths = dd.detect(root, with_processes=False)
        kinds = {(f["flavor"], f["mode"]) for f in findings}
        self.assertIn(("dolt", "repo"), kinds)
        self.assertIn(("doltlite", "file"), kinds)
        self.assertEqual(len(sqlite_paths), 1)
        repo = next(f for f in findings if f["mode"] == "repo")
        self.assertIn("sqlite-runtime + Dolt-system-of-record", repo["evidence"])

    def test_clean_negative(self):
        root = self._make_tree({"README.md": "nothing to see", "app.py": "x = 1"})
        findings, sqlite_paths = dd.detect(root, with_processes=False)
        self.assertEqual(findings, [])
        self.assertEqual(sqlite_paths, [])


class TestClientFlavorSeam(unittest.TestCase):
    """The client must derive its connect flag from the shared map — no hardcode."""

    def test_client_imports_shared_map_and_has_no_hardcoded_flag(self):
        src = open(os.path.join(_SCRIPTS, "dolt-mcp-client.py")).read()
        self.assertIn("FLAVOR_CONNECT[flavor]", src)
        self.assertNotIn('"--stdio", "--dolt"', src)

    def test_client_refuses_stub_flavor(self):
        r = subprocess.run(
            [sys.executable, os.path.join(_SCRIPTS, "dolt-mcp-client.py"),
             "--flavor", "doltlite", "--port", "1", "list_databases"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("decision 6", r.stderr)


if __name__ == "__main__":
    unittest.main()
