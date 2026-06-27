# VERIFIED IRIS API (DFIR-IRIS v2.4.20) — 2026-06-27

Probed live against http://localhost:8000 with a real IRIS_API_KEY (Task 1 of the v2 enrichment plan).

## IOC add — CONFIRMED
`POST /case/ioc/add?cid=<case_id>`
Body: `{ioc_type_id, ioc_value, ioc_description, ioc_tags, ioc_tlp_id}` → 200 `{status:success, data:{ioc_id,...}}`

### IOC type IDs (corrected — assumed values were WRONG)
| type | real type_id | assumed (wrong) |
|------|--------------|-----------------|
| ip-src | 79 | 1 |
| domain | 20 | 20 ✓ |
| url | 141 | 22 |
| md5 | 90 | 90 ✓ (hash) |
| sha1 | 111 | — |
| sha256 | 113 | — |
(ip-any=76, ip-dst=77 also exist.)

## Notes — CHANGED in v2.4.0; require a directory
- `POST /case/notes/groups/list` → 410 deprecated.
- `GET /case/notes/directories/filter?cid=<id>` → list existing directories.
- `POST /case/notes/directories/add?cid=<id>` body `{"name":"SIEM Enrichment"}` → 200 `{data:{id}}`.
- `POST /case/notes/add?cid=<id>` body `{note_title, note_content, directory_id}` → 200. **directory_id is REQUIRED** (omitting it → 400 "non null expected").

## Required workflow fixes
1. Build IRIS Payloads: IOC_TYPE_ID map → `{ip:79, domain:20, url:141, hash:<by length: 32→90 md5, 40→111 sha1, 64→113 sha256, else 90>}`.
2. Post Note path: add a "Ensure Note Directory" HTTP node (create directory, capture id) BEFORE Post Note; Post Note must send `directory_id`.

---
# Runtime verification findings (2026-06-27, live stack)

Ran offenses through the full chain (main workflow → Execute Sub-workflow → enrichment) with providers unavailable (no API keys).

## C1 — CONFIRMED real, FIXED & verified
- Bug: `executeWorkflow` (v1.1) `defineBelow` inputs did NOT reach `Build Targets` with a bare v1 `executeWorkflowTrigger` → every offense hit the empty sentinel ("No external indicators"), 0 IOCs.
- Also found: `Enrich Case.workflowId` must be a resource-locator object `{__rl,value,mode:'id'}`, not a plain string (n8n error "No information about the workflow to execute").
- Fix (verified): main workflow builds a passthrough item via new **Build Enrich Input** Code node ({case_id,indicator,indicator_type,source_ip}); `Enrich Case` simplified (RL workflowId, no defineBelow); sub **Enrichment Trigger → typeVersion 1.1, inputSource: passthrough**.
- PROOF: after fix, execution data shows Build Targets emitting 6 work items + cache keys (enrich:abuseipdb:ip:45.83.122.10, …). Inputs now arrive. ✅

## OPEN BUG — Route Provider (Switch v3) routes nothing
- Symptom: execution reaches `Route Provider` but none of AbuseIPDB/Shodan/OTX run; items dropped (fallbackOutput none). Enrichment never reaches Aggregate/IRIS-post → 0 IOCs, no note.
- Work items entering the Switch are correct (provider='abuseipdb'/'shodan'/'otx' confirmed in execution data).
- Tried: adding `id` to each condition (the working IF nodes have ids) — did NOT fix.
- Next: rebuild Route Provider with the exact n8n Switch-v3 rules schema (check `renameOutput`/output-index handling) OR replace the single Switch with three Filter/IF nodes (IF v2 routes correctly elsewhere in this workflow). Then re-verify the IRIS note+IOC posting tail (note directory + corrected IOC type ids already verified working via direct API).
