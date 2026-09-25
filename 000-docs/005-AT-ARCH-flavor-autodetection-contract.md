# 005-AT-ARCH — The flavor auto-detection contract (`dolt-detect.py`)

**Date:** 2026-07-17 · **Status:** shipped (v0.2.0) · **Builds on:** 002 (blueprint §2 descriptor,
§3 mutation gate), 003 (platform inversion), 004 (engineering panel — Phase 0 gates)

The blueprint (002) designed a dialect-invariant core with maturity-gated flavor adapters, but
left the *entry* question unanswered: how does the plugin know which flavor/mode a user's
workspace actually holds? This document records the detection contract that closes that gap —
the owner's directive verbatim: *"this plugin should accommodate every make and model of Dolt
there is — that's step one: when anyone uses this plugin, what kind of database are we working
with?"*

## 1. Contract

`scripts/dolt-detect.py [PATH] [--endpoint HOST:PORT]` → ranked **findings**, each carrying
`(flavor, mode, endpoint, database, evidence)` and assembled into a **connection descriptor**
(the 002 §2 shape + one additive field `mode`). Detection output IS a descriptor: it feeds
`descriptor-to-mcp-args.py` (validation + wire transform) and `dolt-mcp-client.py
--descriptor` (connection, flavor honored) unchanged. Exit 0 = findings; 1 = honest negative;
2 = usage error. The detector is **read-only** — it never starts, stops, or writes to any
database.

## 2. Taxonomy and probe order

Probes run cheapest-first; every finding names its evidence.

1. **Directory layout** (bounded `os.walk`, never following symlinks; `.git`/`node_modules`/
   `__pycache__`/`.venv` pruned): every `.dolt/` parent is classified by context —
   under `.beads/embeddeddolt/` → `dolt/embedded`; under `.beads/dolt/` → `dolt/server`
   (store); anywhere else → `dolt/repo`. The bd data-dir *roots* (`.beads/dolt`,
   `.beads/embeddeddolt`) carry their own `.dolt` marker but are **not databases** — only
   their children are findings.
2. **`.beads/metadata.json`** (`dolt_mode`/`dolt_database`) — corroborates a layout finding
   (evidence is merged) or contributes one of its own. A `"server"` marker is never claimed
   live by itself.
3. **Process table** (`pgrep` + `/proc`): each live `dolt sql-server` is matched to a store by
   cwd-containment, and its port is the **actual bound LISTEN port** read from
   `/proc/<pid>/net/tcp[6]` via the process's socket inodes — **never** the config.yaml /
   `-P` declared value (bd servers routinely bind ephemeral ports that differ; when declared ≠
   bound, the evidence says so explicitly). A `dumbo` process yields a `dumbo/server` finding
   (experimental — detect-and-report only).
4. **File headers**: a candidate single-file DB (`.db`/`.sqlite`/`.sqlite3`/`.doltlite`) whose
   first 4 bytes are `b"CTLD"` is **DoltLite** — the chunk-store manifest magic
   (`CHUNK_STORE_MAGIC 0x444C5443`, written little-endian by `CS_WRITE_U32`; verified against
   `dolthub/doltlite` `src/chunk_store.h` on 2026-07-17). The 16-byte `SQLite format 3\0`
   header is **plain SQLite** — noted, never claimed as Dolt. A plain-SQLite runtime paired
   with a `dolt/<name>/` system-of-record sidecar in the same directory (the DoltLite-shaped
   pattern, e.g. freshie) is recorded as evidence on the repo finding.
5. **Wire probe** (`--endpoint`): the MySQL initial handshake is read unprompted and its
   version string parsed. Substring matching is ordered `dumbo` > `doltgres` > `dolt` (both
   contain "dolt"). **Empirical finding:** a real `dolt sql-server` (dolt 2.1.10) greets with
   a plain MySQL version (`8.0.33`) — the greeting alone cannot confirm Dolt. The detector
   therefore cross-checks the port against live `dolt sql-server` processes for evidence-based
   confirmation; failing that, the endpoint is reported **unconfirmed** with the exact
   follow-up (`SELECT dolt_version()`). A non-MySQL open port is reported as such (Doltgres
   requires a credentialed Postgres session to confirm — reported, not guessed).

## 3. Ranking and mixed layouts

`live-server (0) > repo (1) > embedded (2) > file (3)`, live before at-rest, stable by path.
A migrated workspace holding **both** `.beads/dolt/` and `.beads/embeddeddolt/` returns
**both** findings in that order. A server-mode store with no live server degrades honestly to
an at-rest store ("no live server matched") — it is still a `.dolt` you can read with CLI
verbs.

## 4. Mode semantics downstream (the honesty rules)

| mode | descriptor endpoint | `descriptor-to-mcp-args` | posture |
|---|---|---|---|
| `server` | `host:port` | transforms (flavor → `--dolt`/`--doltgres`) | wire work via pinned `dolt-mcp-server` |
| `repo` | `file:<path>` | **refuses** (CLI-verb posture) | full dolt CLI verbs |
| `embedded` | `file:<path>` | **refuses** | read-only CLI verbs — the single-writer `.lock` belongs to the embedding tool; mutation refused with that reason |
| `file` (doltlite) | `file:<path>` | **refuses** (decision-6 stub + mode) | detect + report; local `doltlite` CLI; alpha ⇒ read-only |

An absent `mode` is treated as `server` — pre-mode descriptors keep working unchanged
(additive-only evolution). The client (`dolt-mcp-client.py`) imports the flavor→flag map from
the transform module (single source, no duplication) and refuses stub flavors and non-server
descriptors with the same reasons; the hardcoded `--dolt` is gone.

## 5. What each maturity may do

Unchanged from 002 §3 / the sql_classifier gate: `ga`/`beta` — reads free, safe-writes behind
`--allow-mutation` + non-main branch; `alpha`/`experimental` — read-only; history-affecting
statements always refused. Detection changes none of this; it only supplies the correct
`maturity` per flavor (`dolt` ga, `doltgres` beta, `doltlite` alpha, `dumbo` experimental) so
the gate engages automatically.

## 6. Verification record (2026-07-17)

- Unit: `tests/test_dolt_detect.py` (30 tests) — layout incl. mixed + data-dir-root,
  metadata, wire strings, **ephemeral-port-over-declared** (`/proc` fixture), DoltLite/SQLite
  headers, descriptor assembly + downstream refusals, client seam (no hardcoded flag).
- Live estate matrix (read-only): classic repo (freshie sidecar, with SQLite pairing
  evidence) · live server-mode (qmd-team-intent-kb, actual bound port 39353 from `/proc`) ·
  embedded (intent-os `spine`, layout + metadata corroboration) · mixed (hustle, both
  findings ranked) · clean negative — all correct.
- End-to-end zero-config: `--emit-descriptor` → transform validates → `dolt-mcp-client.py
  --descriptor … list_databases` against the live server succeeded with no hand-written
  config.
- Doltgres: transform emits `--doltgres` (unit-verified); **no live Doltgres exists on this
  box** — the wire-level confirmation path is fixture-covered only. Recorded honestly.
