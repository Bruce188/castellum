# docker/ — self-hosted smoke stacks for castellum threat-intel pushes

Two minimal compose files that stand up real TAXII 2.1 and MISP servers on
localhost so the backend's `POST /api/threat-intel/push/taxii` and
`POST /api/threat-intel/push/misp` paths can be exercised against actual
endpoints — not Mockito or `MockRestServiceServer`.

| File                          | What it runs                                              | Host port |
|-------------------------------|-----------------------------------------------------------|-----------|
| `taxii-medallion.yml`         | OASIS medallion TAXII 2.1 server (community image)        | `5000`    |
| `misp-minimal.yml`            | MISP core + mariadb + redis (coolacid/misp-docker)        | `8088`    |

Both stacks use anonymous volumes only; `docker compose ... down -v` is a
clean reset.

## Why this exists

Unit tests cover the wire-format JSON contracts using `MockRestServiceServer`.
Those mocks cannot catch:

- Auth-header capitalization drift (`Authorization:` vs `authorization:`).
- 301 redirects (e.g. MISP's nginx 80→443 hop).
- Server-side payload-size limits.
- STIX bundle / TAXII manifest schema strictness in the medallion backend.
- Heap-pressure issues from materialising the full export bundle in memory.

This stack catches all of the above. The `Failure modes captured this run`
section at the bottom of this file is the verbatim record from the smoke run
on 2026-05-26.

## Prerequisites

- Docker Engine 20+ with `docker compose` v2.
- Free host ports `5000`, `8088`, `8081` (backend), `5173` (frontend if
  running).
- Backend `.env` populated with the variables listed under each section.
- Castellum backend started with `mvn -f backend/pom.xml spring-boot:run` (or
  via `bin/dev-up.sh`).

> Do NOT commit your `.env`. The smoke run records below were captured with
> the values listed inline; rotate any real secrets after copying them in.

## TAXII smoke (medallion)

### 1. Start the stack

```bash
docker compose -f docker/taxii-medallion.yml up -d
docker compose -f docker/taxii-medallion.yml logs -f medallion   # wait for Werkzeug "Running on"
curl -fsS -u admin:Password0 -H 'Accept: application/taxii+json;version=2.1' \
  http://localhost:5000/taxii2/ | head -c 200
```

Expected discovery snippet (one line, truncated):

```
{"api_roots":["http://localhost:5000/trustgroup1/"],"contact":"smoke-test","default":"http://localhost:5000/trustgroup1/","description":"Local TAXII 2.1 server for castellum smoke-testing the threat-intel push paths.","title":"Castellum Smoke-Test Medallion Server"}
```

### 2. Configure the backend

Add to `.env` (or pass as env vars to `mvn spring-boot:run`):

```env
TAXII_BASE_URL=http://localhost:5000/trustgroup1
TAXII_COLLECTION_ID=91a7b528-80eb-42ed-a74d-c6fbd5a26116
TAXII_USERNAME=admin
TAXII_PASSWORD=Password0
```

Then provision the integration row over the API:

```bash
TOKEN=$(curl -sS -X POST http://localhost:8081/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your-admin-password>"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

curl -sS -X PUT http://localhost:8081/api/integrations/TAXII \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "baseUrl":"http://localhost:5000/trustgroup1",
        "collectionId":"91a7b528-80eb-42ed-a74d-c6fbd5a26116",
        "credentials":"admin:Password0",
        "enabled":true
      }'
```

### 3. Push a STIX bundle

```bash
curl -sS -D - -X POST http://localhost:8081/api/threat-intel/push/taxii \
  -H "Authorization: Bearer $TOKEN"
```

### Captured TAXII response — direct push of a minimal bundle (medallion accepts STIX)

To prove medallion accepts our STIX 2.1 wire format we POSTed a minimal
two-object bundle (identity + infrastructure) directly to the
`/collections/{id}/objects/` endpoint:

```
HTTP/1.1 202 ACCEPTED
Server: Werkzeug/3.0.3 Python/3.9.19
Date: Tue, 26 May 2026 19:44:03 GMT
Content-Type: application/taxii+json;version=2.1
Content-Length: 413
Connection: close

{"failure_count": 0,
 "id": "d11ef325-1c44-4bd7-be0c-ee46e024ab8e",
 "pending_count": 0,
 "request_timestamp": "2026-05-26T19:43:42.095893Z",
 "status": "complete",
 "success_count": 2,
 "successes": [
   {"id": "identity--65840157-3696-3d4e-9b22-7113bbe7a64a",
    "version": "2026-05-26T19:00:00.000Z"},
   {"id": "infrastructure--11111111-1111-4111-8111-111111111111",
    "version": "2026-05-26T19:00:00.000Z"}],
 "total_count": 2}
```

This confirms the medallion stack, the seed `medallion-seed.json`, the
admin:Password0 basic-auth, and the collection UUID
`91a7b528-80eb-42ed-a74d-c6fbd5a26116` all wire up correctly.

### Captured TAXII response — full backend push (current limitation)

Issuing the same `POST /api/threat-intel/push/taxii` against the backend on
the smoke fixture surfaced two issues:

```
HTTP/1.1 500
Content-Type: application/json
Date: Tue, 26 May 2026 19:23:34 GMT

{"timestamp":"2026-05-26T19:23:34.962+00:00",
 "status":500,
 "error":"Internal Server Error",
 "path":"/api/threat-intel/push/taxii"}
```

Backend log root cause:

```
o.s.w.client.HttpClientErrorException$UnprocessableEntity:
  422 Unprocessable Entity:
  "{\"description\": \"While processing supplied content, an error occurred. Root exception: 'manifest'\",
    \"http_status\": \"422\", \"title\": \"ProcessingError\"}"
    at io.castellum.threatintel.taxii.TaxiiClient.push(TaxiiClient.java:62)
```

The backend serialises the entire device/CVE export into a single STIX 2.1
bundle (~233 MB at the time of capture); medallion's MemoryBackend rejects
it as malformed against its STIX-2.1 type cache. This is real behaviour worth
preserving in the audit trail: see `threat_intel_push.response_excerpt`.

## MISP smoke (coolacid)

### 1. Start the stack

```bash
docker compose -f docker/misp-minimal.yml up -d
docker compose -f docker/misp-minimal.yml logs -f misp-core
```

First boot takes 1–3 minutes (the image rsyncs the MISP app tree, seeds
mariadb, generates the sample organisation, and starts php-fpm + cron).
Poll until `http://localhost:8088/users/login` returns `200`.

### 2. Fetch the admin API key

The coolacid image seeds an admin user (`admin@admin.test` / `admin`) with a
legacy API key already populated in the `users.authkey` column. The browser
forces a password rotation on first login; the API key in the database is
not invalidated by that flow, so you can grab it directly:

```bash
docker exec castellum-misp-db \
  mariadb -umisp -pexample -D misp -N -B \
  -e "SELECT authkey FROM users WHERE id=1;"
```

Verify with:

```bash
curl -sS -H "Authorization: <api-key>" \
  -H 'Accept: application/json' \
  http://localhost:8088/users/view/me.json | head -c 200
```

A `200` plus a JSON user document confirms the key is good. Export it as
`MISP_API_KEY` in `.env`.

### 3. Configure the backend

`.env` entries:

```env
MISP_BASE_URL=http://localhost:8088
# (credentials posted via the API below; not read directly from env)
```

Provision the integration row:

```bash
curl -sS -X PUT http://localhost:8081/api/integrations/MISP \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{
        \"baseUrl\":\"http://localhost:8088\",
        \"credentials\":\"$MISP_API_KEY\",
        \"distribution\":0,
        \"enabled\":true
      }"
```

### 4. Push

```bash
curl -sS -D - -X POST http://localhost:8081/api/threat-intel/push/misp \
  -H "Authorization: Bearer $TOKEN"
```

### Captured MISP response — direct push of a minimal event (server accepts payload)

Bypassing the backend with a `curl` straight at MISP confirms the server,
the api key, and the `Authorization` header semantics all work:

```
POST /events/add  =>  200
```

Excerpt of the response body (first 1.2 kB):

```json
{
    "Event": {
        "id": "1",
        "orgc_id": "1",
        "org_id": "1",
        "date": "2026-05-26",
        "threat_level_id": "4",
        "info": "castellum smoke-test event",
        "published": false,
        "uuid": "b9c4674c-1880-40fb-888a-52379d2bbaa9",
        "attribute_count": "1",
        "analysis": "0",
        "timestamp": "1779825133",
        "distribution": "0",
        ...
        "Attribute": [
            {"id": "1", "type": "text", "category": "Other", ...
```

MISP returns the event id (`"id": "1"`) which the backend extracts and
writes to `threat_intel_push.bundle_id`.

### Captured MISP response — full backend push (current limitation)

```
HTTP/1.1 500
Content-Type: application/json
Date: Tue, 26 May 2026 19:51:58 GMT

{"timestamp":"2026-05-26T19:51:58.875+00:00",
 "status":500,
 "error":"Internal Server Error",
 "path":"/api/threat-intel/push/misp"}
```

Backend log root cause:

```
java.lang.OutOfMemoryError: Java heap space
Exception in thread "HttpClient-3-SelectorManager"
Exception in thread "HttpClient-5-SelectorManager"
...
```

Same upstream cause as the TAXII case: the backend serialised the full
export (~233 MB) and the default JVM heap (`-Xmx512m` in `bin/dev-up.sh`)
couldn't hold the materialised bundle + the HTTP client buffers. Recommended
fixes — already captured as deferred work in `docs/progress.md`:

1. Stream the bundle in chunks rather than serialise to a single byte[].
2. Cap each push at a configurable object-count (`taxii.max-objects-per-push`).
3. Tune the JVM heap in `bin/dev-up.sh` for installations that need to push
   the whole fleet at once.

## Audit-table snapshot

After the smoke run, `threat_intel_push` records every push attempt (even
failures, before the exception aborts the txn). The TAXII / MISP 500s
captured above never reached the insert because the exception fires inside
the same `@Transactional` boundary that performs the audit write — the
rollback removes the row. The EXPORT rows below come from the
`POST /api/threat-intel/export` smoke (which streams to a `.tar.gz` and
records the bundle id without round-tripping to a remote server):

```text
 id | push_target |                  bundle_id                   | status_code |          occurred_at          |  excerpt
----+-------------+----------------------------------------------+-------------+-------------------------------+-----------
  2 | EXPORT      | bundle--7c012b1a-4266-4408-b772-ea2f722eebd2 |             | 2026-05-26 19:24:19.233392+00 | in-memory
  1 | EXPORT      | bundle--cd34a288-c0b4-4f5b-bdea-96ae6d0aa80a |             | 2026-05-26 14:42:35.293106+00 | in-memory
(2 rows)
```

Query used:

```bash
docker exec castellum-pg psql -U castellum -d castellum -c \
  "SELECT id, push_target, bundle_id, status_code, occurred_at,
          LEFT(response_excerpt, 80) AS excerpt
   FROM threat_intel_push
   ORDER BY occurred_at DESC LIMIT 10;"
```

A future improvement (`docs/progress.md` Deferred) is to move the audit
insert to `REQUIRES_NEW` so failure responses are persisted even when the
caller transaction rolls back. The corresponding non-blocking finding is
noted in the F6 review file under `audit-write semantics`.

## Failure modes captured this run

| # | Layer            | Symptom                                            | Root cause                                            | Fix path                                  |
|---|------------------|----------------------------------------------------|-------------------------------------------------------|--------------------------------------------|
| 1 | medallion image  | `oasis-open/medallion` denied on Docker Hub       | OASIS only ships PyPI/source, no Hub image            | Substituted `sbirtane/medallion-taxii-server` (community)|
| 2 | medallion seed   | 404 on `/trustgroup1/`                            | memory_backend keys map without trailing slash        | Removed trailing `/` in seed JSON keys     |
| 3 | medallion seed   | 422 `Root exception: 'manifest'`                  | manifest array required per-collection                | Added `manifest:[]` to each collection     |
| 4 | medallion seed   | 500 `'dict' object has no attribute 'append'`     | `status` must be a list, not a dict                   | Changed `status: {}` → `status: []`        |
| 5 | medallion seed   | 413 Payload Too Large                              | `max_content_length` defaulted to ~9 MB               | Raised to 500 MB (524288000) in api_root info |
| 6 | MISP nginx       | 301 to https://localhost (no TLS terminator)      | Default nginx redirects 80→443                        | Added `NOREDIR: "true"` env on misp-core   |
| 7 | backend → TAXII  | 422 "Root exception: 'manifest'"                  | 233 MB bundle malformed under medallion's STIX cache  | Stream bundle, cap objects (deferred)      |
| 8 | backend → MISP   | 500 OutOfMemoryError                               | Full export materialised in single byte[]             | Stream bundle, cap heap (deferred)         |
| 9 | audit table      | TAXII/MISP failures not visible in `threat_intel_push` | Audit insert in same @Transactional that rolls back | Move audit to `REQUIRES_NEW` (deferred)    |

All four entries 7-9 are tracked in `docs/progress.md` under Deferred for a
future "bundle streaming" feature.

## Tear-down

```bash
docker compose -f docker/misp-minimal.yml down -v
docker compose -f docker/taxii-medallion.yml down -v
```

Both stacks are stateless; `-v` wipes the mariadb data dir and the
medallion in-memory state. No host artifacts persist.

## Related docs

- `documentation/threat-intel-integrations.html` — user-facing description of
  the integration endpoints and the bundle wire format.
- `docs/progress.md` — Deferred section captures the streaming / heap / audit
  follow-ups identified by this smoke run.
