# Changelog

All notable changes to the `dolt-mcp-vcs` plugin. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are the plugin manifest versions.

## 0.2.0 — 2026-07-17

**Flavor auto-detection: the plugin now answers "what kind of Dolt database am I working
with?" for every make and model, before doing any work.** Contract spec:
`000-docs/005-AT-ARCH-flavor-autodetection-contract.md`.

### Added
- `scripts/dolt-detect.py` — universal, stdlib-only, read-only detector. Probes directory
  layout, `.beads/metadata.json`, the process table (matching live `dolt sql-server`
  processes by cwd and reading the **actual bound port from `/proc`**, never config.yaml),
  single-file DB headers (DoltLite chunk-store magic `b"CTLD"`; plain SQLite noted, not
  claimed), and the wire (`--endpoint`, MySQL greeting + live-process cross-check). Returns
  ranked findings, each a ready-to-use connection descriptor; mixed layouts return every
  finding; a miss is an honest "not a Dolt database" plus what was checked.
- Additive `mode` descriptor field (`server`/`repo`/`embedded`/`file`); absent mode still
  means `server`, so existing descriptors work unchanged. Non-server modes are refused by
  the wire transform with a CLI-verb-posture explanation.
- `dolt-mcp-client.py --descriptor` / `--flavor` — zero-hand-written-config connection from
  an emitted descriptor.
- `tests/test_dolt_detect.py` (30 tests) — wired into the safety-gates CI alongside the
  existing three suites.

### Changed
- `dolt-mcp-client.py` no longer hardcodes `--dolt`: the connect flag derives from the
  shared `FLAVOR_CONNECT` map (imported from `descriptor-to-mcp-args.py`, not duplicated),
  which makes Doltgres genuinely connectable end-to-end. The doltlite/dumbo decision-6
  fail-closed stubs are unchanged.
- `SKILL.md`: Step 0 is now *detect* — findings are presented with evidence before any
  routing; honest-degradation rules stated. Skill/plugin version 0.2.0.
- README rewritten around the detection contract (why-this-exists, the taxonomy table,
  declared mutation posture, any-consumer install).

## 0.1.0 — 2026-06-29

Initial `dolt-mcp-vcs` identity release (renamed from `beads-dolt`, non-breaking): the beads
(bd) use-case adapter, five expert agents, the wired pinned `dolt-mcp-server` (v0.3.6), the
verb-class mutation gate (`sql_classifier.py`), the fail-closed creds-ref resolver, the
connection-descriptor validator/transform, and the Phase-0 safety gates CI.
