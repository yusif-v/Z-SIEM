---
type: project
slug: z-siem
status: active
visibility: public
start_date: 2026-06-24
target_date:
repo:
website:
tech: [docker, n8n, dfir-iris, postgresql, python, rabbitmq, redis]
tags: [devsecops, siem-automation, soar, orchestration]
summary: Zero-touch SIEM automation stack connecting SIEM offenses to DFIR-IRIS case management with SLA tracking.
cover:
---

# Z-SIEM

> Zero-touch SIEM automation stack — webhook-driven offense ingestion, case creation, and SLA tracking between SIEMs and DFIR-IRIS.

## Status

**Current:** active

Latest update — 2026-06-24: Phase 1 MVP — N8N + DFIR-IRIS integration with SLA timer.

## Overview

Z-SIEM is an open-source orchestration layer that bridges the gap between SIEM detection and incident response. It ingests offense alerts via webhooks, automatically creates cases in DFIR-IRIS, starts SLA timers, and tracks resolution metrics — all without manual intervention.

**Phase 1 (current):** N8N receives SIEM offenses via webhook, creates IRIS cases with type-based classification, and tracks case lifecycle (SLA start/close duration) end-to-end.

## Features

- **Webhook offense ingestion** — Accepts structured SIEM payloads (Splunk ES, Sentinel, QRadar format compatible)
- **Automated case creation** — Creates DFIR-IRIS cases with type-based classification
- **SLA timer tracking** — Records case creation time, calculates duration on close
- **JSONL metrics export** — SLA metrics written to file for future Grafana/dashboard integration
- **Demo simulator** — Python script generates synthetic offenses for testing
- **Docker Compose** — Single-command deployment of entire stack
- **Threat-intel enrichment (v2)** — On case creation, indicators are enriched via AbuseIPDB/Shodan/AlienVault OTX (best-effort, Redis-cached) and attached as an IRIS note + registered IOCs. Never blocks the webhook; never changes classification.

## Tech Stack

| Component | Role | Port |
|-----------|------|------|
| N8N | Workflow engine (v2.27.4) | 5678 |
| DFIR-IRIS | Case management | 8000 |
| PostgreSQL | Database (IRIS + N8N) | 5432 |
| Redis | Cache / session store | 6379 |
| RabbitMQ | Message broker (IRIS workers) | 5672/15672 |
| Python 3 | SIEM simulator script | — |

## Architecture

```
┌─────────────────┐     webhook      ┌──────────────────┐     API     ┌─────────────┐
│  SIEM Simulator │ ───────────────> │  N8N Workflow    │ ──────────> │ DFIR-IRIS   │
│  (Python)       │                  │                  │             │ (Case Mgmt) │
└─────────────────┘                  │  1. Parse        │             └─────────────┘
                                     │  2. Create case  │                    │
┌─────────────────┐                  │  3. Start SLA    │                    │
│  Analyst        │ ── close case ──> │  4. Close case   │ <──────────────────┘
│  (UI or API)    │                  │  5. End SLA      │
└─────────────────┘                  │  6. Log metrics  │
                                     └──────────────────┘
                                            │
                                            ▼
                                     ┌──────────────┐
                                     │ JSONL Metrics│
                                     │ (SLA logs)   │
                                     └──────────────┘
```

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.8+ (for simulator)

### 1. Start + bootstrap (turnkey)

```bash
cd Z-SIEM
./z-siem.sh start        # bring up the 6 services (IRIS takes ~90s on first run)
./z-siem.sh bootstrap    # provision n8n creds + import/activate all 3 workflows
```

`bootstrap` is **idempotent** and fully automated — it reads the IRIS admin API
key straight from the database (syncing it into `.env`), creates the n8n
credentials (`IRIS API Key`, `Z-SIEM Redis`), and imports + activates all three
workflows (Offense-to-Case, Enrichment, SLA Poller). No manual UI steps.

> Optional: add provider API keys to `.env` (`ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`,
> `OTX_API_KEY`) for live threat-intel enrichment, then re-run `bootstrap`.
> Without them, enrichment still runs and posts a note marking providers
> "unavailable".

<details><summary>Manual setup (if you prefer the n8n UI)</summary>

`./z-siem.sh setup` prints the checklist: create the `IRIS API Key` (Header Auth)
and `Z-SIEM Redis` credentials, import the three workflow JSONs from
`n8n/workflows/`, and activate them.
</details>

### 2. Run the demo

```bash
./z-siem.sh demo
```

Sends 3 synthetic offenses through the full lifecycle. Check N8N executions and IRIS cases.

### 3. Manual testing

Send a single offense:
```bash
curl -X POST http://localhost:5678/webhook/siem-offense \
  -H "Content-Type: application/json" \
  -d '{
    "offense_id": "TEST-001",
    "severity": "critical",
    "type": "malware_c2",
    "description": "Test offense",
    "indicator": "203.0.113.50",
    "indicator_type": "source_ip",
    "confidence": 95,
    "source": {"ip": "203.0.113.50", "hostname": "TEST-PC"},
    "asset": {"hostname": "TEST-PC", "ip": "10.0.1.50", "criticality": "high"}
  }'
```

Close the case:
```bash
curl -X POST http://localhost:5678/webhook/siem-close-case \
  -H "Content-Type: application/json" \
  -d '{"case_id": 1, "close_reason": "resolved"}'
```

## Deploy on a Linux server

The repo is the code; **secrets are not in git**. `.env` is gitignored, so a
`git pull` brings everything *except* your credentials — you create `.env` on the
server. As of the security hardening, **`IRIS_ADM_PASSWORD` is required**: Docker
Compose refuses to start if it is unset (no insecure default ships in the image).

### 1. Prerequisites (Ubuntu/Debian example)

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin git
sudo usermod -aG docker "$USER"   # log out/in so docker runs without sudo
```

### 2. Clone the repo

```bash
git clone git@github.com:yusif-v/Z-SIEM.git
cd Z-SIEM
```

### 3. Create `.env` with strong secrets

```bash
cp .env.example .env
```

Then edit `.env` and set real values. **Generate fresh secrets — never reuse the
demo defaults in production:**

```bash
# strong random helpers
openssl rand -hex 64   # → IRIS_SECRET_KEY
openssl rand -hex 16   # → IRIS_SECURITY_SALT
openssl rand -base64 24 | tr -d '/+=' | head -c 28; echo   # → each password
```

Required keys: `IRIS_ADM_PASSWORD` (admin login, user `administrator`),
`IRIS_DB_PASSWORD`, `IRIS_REDIS_PASSWORD`, `IRIS_RABBITMQ_PASSWORD`,
`IRIS_SECRET_KEY`, `IRIS_SECURITY_SALT`, `N8N_DB_PASSWORD`, `N8N_PASSWORD`.
Leave `IRIS_API_KEY` as a placeholder — it is generated on first boot.
Lock the file down: `chmod 600 .env`.

> Transfer secrets securely — `scp .env user@server:/path/Z-SIEM/.env` or paste
> over SSH. Do **not** commit `.env` or send it over insecure channels.
> `IRIS_SECRET_KEY` and `IRIS_SECURITY_SALT` must stay stable after first boot —
> changing them later invalidates sessions and stored password hashes.

### 4. Start the stack

```bash
docker compose up -d          # first boot creates 'administrator' with IRIS_ADM_PASSWORD (~90s for IRIS)
./z-siem.sh bootstrap         # fetch IRIS API key into .env + provision n8n creds/workflows
```

On a fresh server this is a clean first boot, so `IRIS_ADM_PASSWORD` is applied
automatically — no database reset needed. (A reset is only required if you change
the admin password *after* IRIS has already initialized its database, since the
admin account is created once on first boot.)

### 5. Verify

```bash
docker compose ps                         # all services healthy
curl -sf http://localhost:8000/login >/dev/null && echo "IRIS up"
```

Log in to IRIS at `http://<server-ip>:8000` as `administrator` with your
`IRIS_ADM_PASSWORD`, and n8n at `http://<server-ip>:5678` (user `admin`,
password `N8N_PASSWORD`).

> **Exposing to a network:** the ports above bind to the host directly. For
> anything beyond a trusted LAN, put IRIS/n8n behind a reverse proxy with TLS and
> restrict `5432`/`6379`/`5672`/`15672` to localhost or the Docker network only.

## SLA Tracking

The case **description is a markdown template** (rendered by IRIS) with a detection
table and an **SLA / Case lifecycle** section. On creation the workflow writes the
🟢 Opened timestamp, the severity-based **target**, and the **due-by** time. On
close it writes the 🔴 Closed timestamp, **time-to-resolve**, and a **✅ Met /
❌ Breached** status — directly into the case.

**Closing a case (two ways, both write the SLA):**
- **Close webhook** (`/webhook/siem-close-case`) → closes the IRIS case and writes
  the SLA instantly.
- **IRIS GUI** (Close case button) → the **Z-SIEM SLA Poller** workflow checks IRIS
  every minute for newly-closed cases with a pending SLA and fills it in (≤1 min).

A `sla_started` / `sla_closed` event is also appended to a JSONL metrics log.

**Target policy** (severity-based, written into each case):

| Severity | Target |
|----------|--------|
| critical | 4 hours |
| high | 8 hours |
| medium | 24 hours |
| low | 24 hours |

Note: IRIS **case classification** is assigned from the offense `type` (not severity): `malware_c2`/`ransomware_indicator` → 3, `lateral_movement`/`privilege_escalation` → 2, all others → 1.

Metrics are logged to `/home/node/.n8n/workspace/siem-sla-metrics.jsonl` inside the N8N container:

```jsonl
{"case_id": 1, "offense_id": "OFF-2026-1001", "sla_start": "2026-06-24T12:00:00Z", "severity": "critical", "event": "sla_started"}
{"case_id": 1, "sla_start": "2026-06-24T12:00:00Z", "sla_end": "2026-06-24T12:05:00Z", "sla_duration_seconds": 300, "event": "sla_closed"}
```

## Project Structure

```
Z-SIEM/
├── docker-compose.yaml          # Full stack definition
├── z-siem.sh                    # Stack manager script
├── .env.example                 # Environment template
├── config/
│   ├── iris/                    # IRIS configuration files
│   ├── n8n.env                  # N8N environment variables
│   └── postgres/
│       └── init-n8n-db.sh       # Multi-database initialization
├── n8n/
│   ├── workflows/
│   │   ├── z-siem-offense-to-case.json  # Main workflow
│   │   └── z-siem-enrichment.json       # Enrichment sub-workflow
│   └── workspace/               # Runtime (gitignored)
├── scripts/
│   ├── siem_simulator.py        # Offense simulator
│   └── requirements.txt         # Python dependencies
└── docs/                        # Additional documentation
    └── workflows/               # Workflow diagrams & docs (see below)
```

### Workflow documentation

Detailed, diagrammed docs for both n8n workflows live in
[`docs/workflows/`](docs/workflows/README.md):

- [Offense-to-Case](docs/workflows/offense-to-case.md) — webhooks, IRIS case creation, SLA tracking
- [Enrichment](docs/workflows/enrichment.md) — threat-intel fan-out, Redis cache, IOC/note write-back

## Roadmap

- [x] Phase 1: N8N + DFIR-IRIS integration with SLA tracking
- [ ] Phase 2: SIEM-specific webhook adapters (Splunk ES, Sentinel, QRadar)
- [x] Phase 3: Automated triage enrichment (AbuseIPDB / Shodan / OTX → notes + IOCs)
- [ ] Phase 4: ML-based offense classification (Sphinx model integration)
- [ ] Phase 5: SLA reporting dashboard (Grafana + JSONL connector)
- [ ] Phase 6: Multi-tenancy support (customer-scoped cases)
- [ ] Phase 7: SOAR playbook library (20+ prebuilt response actions)

## Links

- Repository: (local vault project)
- Demo: (run `./z-siem.sh demo`)
- N8N Docs: https://docs.n8n.io/
- DFIR-IRIS Docs: https://docs.dfir-iris.org/

## Notes

- Default credentials are for demo only — change all passwords for production
- IRIS initial login: complete the setup wizard on first visit
- The N8N workflow uses Header Auth credential type (not stored in workflow JSON)
- PostgreSQL creates two databases: `iris` (IRIS app) and `n8n` (N8N workflows)
- All services communicate on the `z-siem-network` Docker bridge network

## v2 Enrichment Setup

Phase 3 adds a sub-workflow (`z-siem-enrichment.json`) that fires after every case creation and enriches the indicator with threat-intel data from three providers.

### API Keys

Add the following to your `.env` before starting the stack:

```env
# AbuseIPDB — https://www.abuseipdb.com/account/api
ABUSEIPDB_API_KEY=your_key_here

# Shodan — https://account.shodan.io/
SHODAN_API_KEY=your_key_here

# AlienVault OTX — https://otx.alienvault.com/api
OTX_API_KEY=your_key_here
```

All three lookups are best-effort: if a key is missing or a provider is down the enrichment node logs the error and exits cleanly — it never blocks the webhook ack or alters the case classification.

### Redis (already in stack)

The existing `redis` service in `docker-compose.yaml` is reused for enrichment caching. Create a **Z-SIEM Redis** credential in N8N (type: Redis):
- Host: `redis`
- Port: `6379`
- Password: value of `IRIS_REDIS_PASSWORD` from your `.env`

### Importing the workflows

`./z-siem.sh bootstrap` imports and activates all three workflows with pinned
ids and credential bindings — no manual workflow-id juggling. The workflow JSONs
in `n8n/workflows/` carry stable ids (`zsiemEnrichWf01`, etc.) so the
Offense-to-Case → Enrichment link resolves automatically on any server.

> n8n 2.x requires a sub-workflow to be **active** to be called via Execute
> Workflow, and blocks `$env` in expressions unless `N8N_BLOCK_ENV_ACCESS_IN_NODE`
> is set (both handled in `docker-compose.yaml` + the bootstrap).

### Credentials (auto-created by bootstrap)

| Credential name | Type | id | Used by |
|-----------------|------|----|---------|
| IRIS API Key | Header Auth | `iris-api-key` | Create/Close/Get/Update + enrichment HTTP nodes |
| Z-SIEM Redis | Redis | `zsiemRedisCred01` | Enrichment cache |

## Log

- 2026-06-24: created — Phase 1 MVP with docker-compose, N8N workflow, and SIEM simulator
- 2026-06-27: Phase 3 — enrichment sub-workflow wired; AbuseIPDB/Shodan/OTX integration; Redis cache
- 2026-06-29: upgraded n8n 1.74.1 → 2.27.4; markdown case template + in-case SLA (opened/closed/breach); GUI-close SLA poller; fixed enrichment for n8n 2.x (Redis/HTTP item-stripping, provider fan-in); turnkey `bootstrap`
