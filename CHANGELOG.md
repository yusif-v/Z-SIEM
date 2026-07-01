# Changelog

All notable changes to **Z-SIEM** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-07-01

QRadar offense ingestion via scheduled API polling.

### Added
- **QRadar Offense-to-Case workflow** (`z-siem-qradar-poller.json`) — polls
  `GET /api/siem/offenses?filter=status=OPEN` every minute (`SEC` header via the
  `QRadar SEC` credential; `Range: items=0-199` header), maps QRadar
  magnitude/`offense_type`/`offense_source`/categories/rules into the shared
  markdown case + SLA pipeline, and reuses the Enrichment sub-workflow for IP
  indicators. Closes are still completed by the SLA Poller (same sentinels).
- **Offense dedup** — `qradar-seen-offenses.json` maps `offense_id → case`; only
  written on successful case creation so failures retry. Code nodes `mkdir -p`
  the workspace dir first so the state persists (a missing dir was the cause of
  duplicate cases).
- **IRIS-failure log** — offenses whose case creation fails are appended to
  `qradar-errors.jsonl` and left unmarked for retry.
- `normalize_workflows.py` now pins the QRadar workflow id (`zsiemQradarWf01`) and
  the `QRadar SEC` credential.
- Docs: [`docs/workflows/qradar-offense-to-case.md`](docs/workflows/qradar-offense-to-case.md).

### Security
- QRadar `SEC` token is referenced via an n8n credential (not hardcoded in the
  workflow JSON), matching the IRIS API key pattern.

## [2.0.0] - 2026-06-29

Enrichment, in-case SLA, and turnkey deployment. First tagged release.

### Added
- **Turnkey `bootstrap`** (`./z-siem.sh bootstrap`) — idempotent provisioning:
  reads the IRIS admin API key from the database into `.env`, creates the n8n
  credentials (`IRIS API Key`, `Z-SIEM Redis`), and imports + activates all three
  workflows. No manual UI steps.
- **Markdown case template** — cases are created with a rendered markdown summary
  (detection table + SLA section).
- **In-case SLA tracking** — Opened timestamp, severity-based target
  (critical 4h · high 8h · medium/low 24h), and due-by written at creation;
  Closed timestamp, time-to-resolve, and ✅ Met / ❌ Breached status written on close.
- **SLA Poller workflow** (`z-siem-sla-poller.json`) — scheduled (1 min) writer that
  fills in the SLA for cases closed directly in the DFIR-IRIS GUI.
- **Threat-intel enrichment** verified end-to-end — per-case sub-workflow queries
  AbuseIPDB / Shodan / OTX (Redis read-through cache), posts a markdown note, and
  registers IOCs back into the case.
- **Workflow documentation** under `docs/workflows/` with validated Mermaid diagrams.
- Pinned, stable workflow + credential ids (`scripts/normalize_workflows.py`) so
  imports bind deterministically on any server.

### Changed
- Upgraded **n8n 1.74.1 → 2.27.4** (data preserved via in-place DB migration).
- Close path now writes the SLA back into the case (`Get Case` → `Patch SLA Block`
  → `Write SLA to Case`).
- README rewritten around the turnkey bootstrap flow; documented GUI-close SLA.

### Fixed
- n8n 2.x blocked `$env` in node expressions → set `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`.
- n8n 2.x requires a sub-workflow to be **active** to be called via Execute Workflow.
- Re-pinned the Offense-to-Case → Enrichment link (`zsiemEnrichWf01`).
- Enrichment context loss on n8n 2.x: the Redis `get` and provider HTTP nodes now
  replace the item, dropping work-item fields. Added `Merge Cache Fields` and the
  `Ctx` nodes to re-attach `provider` / `case_id` / `target_value`.
- Enrichment produced duplicate notes/IOCs: the three provider branches each
  triggered Aggregate. Added `Merge Providers` and made `Aggregate Verdict` fire
  once, reading fresh + cached results by reference — one offense now yields
  exactly one note + IOC set.

### Security
- `.env` and local `backups/` (DB dumps) are gitignored; no secrets are committed.

## [1.0.0] - 2026-06-24

Initial Phase 1 MVP.

### Added
- Six-service `docker-compose` stack: n8n, DFIR-IRIS, PostgreSQL, Redis, RabbitMQ,
  and a Python SIEM simulator.
- **Offense-to-Case** workflow — webhook ingest, IRIS case creation, SLA start, and
  webhook-driven case close with JSONL SLA metrics.
- `z-siem.sh` stack manager (`start` / `stop` / `status` / `logs` / `demo` / `setup`)
  and `scripts/case.sh` helper for opening/closing cases via webhooks.
- Initial threat-intel enrichment scaffolding (AbuseIPDB / Shodan / OTX, Redis cache).

[2.0.0]: https://github.com/yusif-v/Z-SIEM/releases/tag/v2.0.0
[1.0.0]: https://github.com/yusif-v/Z-SIEM/commits/main
