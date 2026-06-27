# Z-SIEM v2 — Enrichment Sub-Workflow Design

**Date:** 2026-06-27
**Status:** Approved (pending user spec review)
**Roadmap phase:** Phase 3 — Automated triage enrichment
**Depends on:** Phase 1 offense-to-case workflow (`n8n/workflows/z-siem-offense-to-case.json`)

## 1. Goal

Turn the offense-to-case relay into a triage step: when a case is created, enrich its
indicators against external threat-intel providers and attach the findings to the IRIS
case as a note plus registered IOCs — **without** delaying the webhook response and
**without** changing case classification.

Enrichment is **additive only**: it never escalates/downgrades `case_classification`
and never blocks or fails case creation.

## 2. Decisions (locked during brainstorming)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Placement | **Hybrid** — fast case create + async enrich, cache short-circuit | Webhook caller gets `case_id` immediately; enrichment runs in the tail of the same n8n execution. Cache hits make the tail near-instant. |
| Providers | **AbuseIPDB, Shodan, AlienVault OTX** (no VirusTotal) | All free-tier. OTX is the broad source (IP/domain/URL/hash); AbuseIPDB + Shodan add IP-only depth. |
| Verdict effect | **Notes + IOCs only** | Safest — zero risk of mis-escalation. Classification stays type-based. |
| Cache | **Redis** (new compose service) | Clean TTL via SETEX, atomic, native n8n nodes, no file-locking. |
| Failure policy | **Best-effort, partial OK** | Parallel providers, short timeout + 1 retry; failed providers marked `unavailable`, not cached; case never blocked. |

## 3. Architecture

### 3.1 Trigger model (the "hybrid")

The main workflow `z-siem-offense-to-case` is extended by **one** node. After
`Respond OK` fires the HTTP response (caller receives `case_id`), the same n8n
execution continues into a new node:

```
... Store SLA Start → Respond OK  ──→  Enrich Case (Execute Sub-workflow)
```

- **`Enrich Case`** = `n8n-nodes-base.executeWorkflow` node.
- The main execution *does* wait for the sub-workflow to finish, but this is invisible to
  the caller: `Respond OK` already sent the HTTP response, so the webhook ack is not
  blocked. Enrichment completes in the tail of the execution. (No queue/worker needed.)
- Input payload passed to the sub-workflow:
  ```json
  {
    "case_id": "<iris_case_id>",
    "indicator": "<value>",
    "indicator_type": "ip|domain|url|hash",
    "source_ip": "<value or 'unknown'>"
  }
  ```
  `asset_ip` is intentionally **not** passed — it is the internal victim host
  (typically RFC1918) and external reputation lookups on it are noise.

### 3.2 Sub-workflow `z-siem-enrichment`

New file: `n8n/workflows/z-siem-enrichment.json`.

```
Execute-Workflow Trigger
  → Build Targets        (dedup list of {value,type} to enrich)
  → Cache Lookup         (Redis GET per provider×target; split hits vs misses)
  → Provider Fan-out     (parallel HTTP, best-effort; only cache-missed pairs)
  → Aggregate Verdict    (merge cached + fresh → normalized verdict per target)
  → Cache Writes         (Redis SETEX per successful provider result)
  → Post Note to IRIS    (POST /case/notes/add?cid=<case_id>)
  → Register IOCs to IRIS (POST /case/ioc/add?cid=<case_id> per target)
```

## 4. Components

### 4.1 Build Targets (Code node)
Produces the deduplicated list of targets to enrich:
- Always include `{ value: indicator, type: indicator_type }`.
- Include `{ value: source_ip, type: "ip" }` **only if** `source_ip` is a valid
  **public** IP (not `unknown`, not RFC1918/loopback/link-local). Helper: a small
  `isPublicIp()` check in the node.
- Dedup by `type:value`.

### 4.2 Provider routing
| Target type | Providers queried |
|-------------|-------------------|
| `ip`        | AbuseIPDB + Shodan + OTX |
| `domain`    | OTX |
| `url`       | OTX |
| `hash`      | OTX |

### 4.3 Cache (Redis)
- **Key:** `enrich:<provider>:<type>:<value>` (e.g. `enrich:abuseipdb:ip:1.2.3.4`).
- **Value:** JSON of that provider's normalized result.
- **TTL (env-configurable, defaults):**
  - AbuseIPDB IP reputation — `ENRICH_TTL_IP=86400` (24h)
  - Shodan host — `ENRICH_TTL_SHODAN=86400` (24h)
  - OTX IP/domain/url — `ENRICH_TTL_OTX=86400` (24h)
  - OTX hash — `ENRICH_TTL_HASH=604800` (7d)
- **Lookup:** for each target, GET each applicable provider key; providers that hit are
  reused, providers that miss are queued for a live call.
- **Write:** only **successful** provider results are SETEX-cached. Failures are not
  cached (so they are retried next time).

### 4.4 Provider calls (HTTP Request nodes, best-effort)
Each provider node:
- Timeout ~5s (`options.timeout: 5000`).
- `retryOnFail: true`, `maxTries: 2` (1 retry), `waitBetweenTries: 1500`.
- `onError: continueRegularOutput` so a failure yields a marker instead of aborting.
- API key from n8n credentials / env (see §6).

Provider endpoints (verify exact paths/params at implementation time):
- **AbuseIPDB:** `GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=90`,
  header `Key: <ABUSEIPDB_API_KEY>`. Extract `data.abuseConfidenceScore`,
  `data.totalReports`, `data.countryCode`.
- **Shodan:** `GET https://api.shodan.io/shodan/host/<ip>?key=<SHODAN_API_KEY>`.
  Extract `ports`, `vulns`, `org`. A 404 (no info) is a valid "clean" result, not a failure.
- **OTX:** `GET https://otx.alienvault.com/api/v1/indicators/<section>/<value>/general`,
  header `X-OTX-API-KEY: <OTX_API_KEY>`, where `<section>` ∈
  `IPv4 | domain | url | file`. Extract `pulse_info.count` and top pulse names.

### 4.5 Aggregate Verdict (Code node)
Normalized per-target verdict:
```json
{
  "value": "1.2.3.4",
  "type": "ip",
  "sources": {
    "abuseipdb": { "confidence": 92, "reports": 41, "country": "RU" },
    "shodan":    { "ports": [22, 80, 443], "vulns": ["CVE-2021-..."] },
    "otx":       { "pulses": 3, "top": ["Emotet C2", "..."] }
  },
  "summary": "AbuseIPDB 92% · OTX 3 pulses · Shodan 3 ports",
  "unavailable": ["shodan"]
}
```
- A provider that failed/timed out appears in `unavailable[]` and is omitted from `sources`.
- `summary` is a human one-liner built from whatever succeeded.

### 4.6 Post to IRIS
- **Note:** `POST {IRIS_API_URL}/case/notes/add?cid=<case_id>` with a markdown body —
  one section per target, a provider table, and the `summary` line. Header auth (reuse
  existing `IRIS API Key` credential).
- **IOCs:** `POST {IRIS_API_URL}/case/ioc/add?cid=<case_id>` per target, mapping
  `type → IRIS ioc_type` (`ip → ip-src`, `domain → domain`, `url → url`, `hash → sha256`)
  with `ioc_value` and `ioc_tags: "siem,enrichment"`.

> ⚠️ **Endpoint verification is the FIRST implementation task.** The exact IRIS note/IOC
> endpoint paths, query params (`cid`), and request schemas must be confirmed against the
> running DFIR-IRIS API version before wiring — the same class of mismatch that required
> the earlier `/manage/cases` corrections. Do not assume these paths are correct.

## 5. Error handling

| Failure | Behavior |
|---------|----------|
| Provider timeout / 5xx / network | After 1 retry, mark provider `unavailable`; continue. |
| Provider 404 (Shodan no-info) | Treat as a valid "no data" result, not a failure. |
| All providers unavailable for a target | Note still posts, stating enrichment was unavailable; no IOC verdict data, but IOC still registered. |
| Redis down | Skip cache (treat every lookup as a miss); enrichment still runs live. Log a warning. |
| IRIS note/IOC POST fails | Log the error in the execution; do **not** retry-loop forever (the case already exists). Best-effort. |

Enrichment failure at any stage **never** affects the already-created case or the
already-sent webhook response.

## 6. Infra & secrets changes

- **docker-compose:** Redis **already exists** as service `redis` (`z-siem-redis`,
  `redis:7-alpine`, password `${IRIS_REDIS_PASSWORD:-redisdemo2026}`, on `z-siem-net`).
  **Reuse it** — no new service. n8n (same network) reaches it at `redis:6379` with that
  password. Isolate from IRIS's keys with the `enrich:*` prefix. (Deviation from original
  brainstorm, which assumed adding a service; discovered already present during planning.)
- **n8n env / `.env`:** new vars
  `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `OTX_API_KEY`,
  `ENRICH_TTL_IP`, `ENRICH_TTL_SHODAN`, `ENRICH_TTL_OTX`, `ENRICH_TTL_HASH`,
  `REDIS_HOST=redis`, `REDIS_PORT=6379` (Redis password reuses `IRIS_REDIS_PASSWORD`).
- **`.env.example` + README:** document the three provider keys (where to get free keys)
  and the new Redis service.
- **n8n credentials:** create header-auth / generic credentials for each provider key so
  workflow JSON references credential IDs, not raw keys.

## 7. Testing

| Test | Method | Pass criteria |
|------|--------|---------------|
| Verdict populated (known-bad) | Fire an offense with a known-flagged IP / EICAR-style hash | Note shows non-empty provider data; IOC registered on case |
| Cache hit | Fire the same offense twice | 2nd run makes **zero** live provider calls (verify via `redis-cli MONITOR` or call counters) |
| Provider down | Point one provider base URL at a dead host | Note still posts; that provider listed under `unavailable` |
| Redis down | Stop the redis container, fire an offense | Enrichment still completes live; warning logged |
| No public source_ip | Offense with RFC1918 `source_ip` | Only `indicator` enriched; `source_ip` skipped |
| Webhook latency unchanged | Time the `/siem-offense` response | Response returns before provider calls complete (ack not blocked) |

## 8. Out of scope (future phases)

- Dead-letter / scheduled retry queue for failed enrichments (considered, deferred).
- Classification escalation from verdict (explicitly rejected — notes/IOCs only).
- VirusTotal integration.
- Dashboarding of enrichment hit rates (Phase 5 Grafana).

## 9. Implementation task order (for the plan)

1. **Verify IRIS note + IOC API endpoints** against the running instance (blocking).
2. Add `redis` service + healthcheck to docker-compose; add env vars + `.env.example`.
3. Create n8n provider credentials.
4. Build `z-siem-enrichment.json` sub-workflow (Build Targets → Cache Lookup →
   Provider Fan-out → Aggregate → Cache Writes → Post Note → Register IOCs).
5. Add `Enrich Case` Execute-Workflow node to `z-siem-offense-to-case.json` after `Respond OK`.
6. Run the §7 test matrix end-to-end.
7. Update README (Features, Roadmap Phase 3 → in-progress/done, providers, Redis).
