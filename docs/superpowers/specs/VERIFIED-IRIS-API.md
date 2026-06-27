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
