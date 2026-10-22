# Idle reaper safety contract (0.2.1)

The reaper is for local, bd-managed Dolt servers whose work lives on `main` and
whose configured account can see every user database. It does not provide an
atomic shutdown or a general multi-branch server shutdown protocol.

## Decision and provenance

Version 0.2.0 skipped a database literally named `dolt` as if it were a system
schema. A dirty `dolt` database alongside a clean project database could therefore
pass its clean gate. Version 0.2.1 treats `dolt` as user data, preserves query exit
status, and accepts only `dirty`, `---`, and a single `0` row. Prefixes such as
`0junk`, extra result rows, and a failed command printing a zero are refused.

The text contract comes from the pinned
[dolthub/dolt-mcp v0.3.6 formatter](https://github.com/dolthub/dolt-mcp/blob/v0.3.6/mcp/pkg/db/database.go),
used by its
[list_databases](https://github.com/dolthub/dolt-mcp/blob/v0.3.6/mcp/pkg/tools/list_databases.go)
and [query](https://github.com/dolthub/dolt-mcp/blob/v0.3.6/mcp/pkg/tools/query.go)
tools. The MCP binary pin and checksum remain owned by
`scripts/dolt-mcp-client.py`; this patch does not upgrade that dependency.

## Required observations

- The activity-file heuristic must indicate at least `IDLE_MIN` idle minutes.
- The candidate must be a direct `dolt sql-server` process in the reaper's network
  namespace. Its file descriptors must own one unambiguous IPv4 listener reachable
  through `127.0.0.1`. Declared ports are not evidence of listener ownership.
- Database discovery and every main-branch status query must succeed through that
  local endpoint. Explicit host, flavor, database, branch, and port flags prevent
  inherited connection defaults from redirecting the observation.
- Only `information_schema`, `mysql`, `performance_schema`, and `sys` are skipped.
  At least one user database must be checked. Unknown formatting or unsupported
  identifier characters keep the server alive.
- Process start ticks, listener port, and observed activity timestamp are rechecked
  after the queries. A changed or missing observation keeps the process alive.

`--dry-run` follows the same checks but sends no signal. Unsupported command-line
arguments and invalid idle thresholds fail before process discovery.

## Limits

A writer can race the final observation and `SIGTERM`; timestamp granularity and
unlogged queries also limit the activity heuristic. This patch does not lock out
writers, enumerate other branches, or prove that the account can see hidden
schemas. Database identifiers must use ordinary single-line ASCII names: the
upstream Markdown formatter does not escape identifiers, so deliberately
ambiguous embedded newlines cannot be disambiguated by this text protocol.

Do not enable automatic reaping for servers outside those assumptions. A server
with multiple IPv4 listeners, IPv6-only binding, inaccessible `/proc`, unexpected
formatting, or a missing helper is retained. Queries themselves may refresh the
activity log and conservatively keep an otherwise idle server. No SIGKILL or
Dolt commit/reset is performed.

## Installation, evidence, and rollback

Distribute `scripts/dolt-idle-reaper.sh` and `scripts/reaper_endpoint.py` together,
alongside the existing MCP client and its dependencies. `BEADS_DOLT_MCP_CLIENT`
can select an installed client; the endpoint helper always stays beside the
reaper. This repository is the source; marketplace and local installed copies
must be updated from the reviewed commit, not independently patched.

Run `python3 -m unittest tests.test_idle_reaper -v` and the existing safety-gates
workflow. Fixtures replace all process discovery, process reads, and signals;
endpoint tests use an artificial proc tree. Never validate by running the real
reaper against live processes, even in dry-run mode.

For rollback, disable the reaper's scheduled invocation first and restore the
prior reviewed plugin revision. Keep scheduling disabled while the old
skip-`dolt` defect is present; leaving servers running is the safe fallback.
This patch does not change a cron job, stop a live server, or migrate any data.
