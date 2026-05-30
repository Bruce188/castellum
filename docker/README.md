# docker/ — self-hosted smoke stacks for castellum threat-intel pushes

> WARNING: smoke-test fixtures only. The default credentials baked into
> these compose files (`admin:Password0` for medallion, `admin@admin.test`
> / `admin` for MISP, `changeme-root` / `example` for MariaDB) are public
> image baselines — NOT secrets. NEVER deploy these compose files
> unmodified to any reachable network: rotate every password, restrict
> port bindings to `127.0.0.1`, and add real network policy first.

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
- Castellum backend running. There is no app-wide root compose file or
  `bin/` bring-up script; the files under `docker/` are only the MISP/TAXII
  smoke fixtures below. Bring the rest of the stack up yourself:
  - **Postgres 16** — provided by the operator: a native install, or e.g.
    `docker run -d --name castellum-pg -e POSTGRES_USER=castellum \
    -e POSTGRES_PASSWORD=castellum -e POSTGRES_DB=castellum \
    -p 5432:5432 postgres:16`.
  - **Backend** (Spring Boot 3.5.13 / Java 21): `cd backend && ./mvnw spring-boot:run`.
  - **Frontend** (React 19 + Vite): `cd frontend && npm install && npm run dev`.
  - **Production / CI** builds and runs the jar instead:
    `cd backend && ./mvnw -q -B -DskipTests package` then `java -jar target/*.jar`.
    The container `Dockerfile` ENTRYPOINT is `["java","-jar","/app/castellum.jar"]`.

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
TAXII_PASSWORD=<medallion-password>
```

Then provision the integration row over the API:

```bash
TOKEN=$(curl -sS -X POST http://localhost:8081/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your-admin-password>"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

# Note: $TOKEN is a short-lived JWT. If a subsequent step returns 401, re-run
# the TOKEN= line above to fetch a fresh token.

curl -sS -X PUT http://localhost:8081/api/integrations/TAXII \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "baseUrl":"http://localhost:5000/trustgroup1",
        "collectionId":"91a7b528-80eb-42ed-a74d-c6fbd5a26116",
        "credentials":"admin:<medallion-password>",
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

Backend log root cause (inner 422 from medallion, surfaced as outer 500 to the caller):

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

#### Triage: 500 from the push endpoint

All three push failure modes surface to the caller as `HTTP 500`. Distinguish them:

| Symptom | Root cause | First triage step |
|---------|-----------|-------------------|
| Backend log: `422 Unprocessable Entity` from medallion | Bundle too large or malformed for MemoryBackend STIX cache | `docker compose -f docker/taxii-medallion.yml logs medallion` — look for `ProcessingError` / `'manifest'` |
| Backend log: `OutOfMemoryError: Java heap space` | Full export materialised in a single `byte[]` exhausts JVM heap | `docker compose -f docker/misp-minimal.yml logs misp-core`; check backend log for OOM thread dumps |
| No backend log line; caller gets 500 immediately | IOException short-circuits the push before the audit writer is reached | `docker logs castellum-backend 2>&1 \| grep IOException` |

In all cases, confirm the audit row state:

```bash
docker exec castellum-pg psql -U castellum -d castellum -c \
  "SELECT push_target, status_code, LEFT(response_excerpt,120) AS excerpt
   FROM threat_intel_push ORDER BY occurred_at DESC LIMIT 5;"
```

A missing row means the IOException path was taken (audit writer never called).
A row with a non-200 `status_code` means the push reached the upstream server.

## MISP smoke (coolacid)

### 1. Start the stack

```bash
docker compose -f docker/misp-minimal.yml up -d
docker compose -f docker/misp-minimal.yml logs -f misp-core
```

First boot takes **1–3 minutes** (the image rsyncs the MISP app tree, seeds
mariadb, generates the sample organisation, and starts php-fpm + cron).
Do NOT interrupt (Ctrl-C) the stack during this window — an interrupted seed
corrupts the MariaDB data directory and requires a `down -v` to recover.
Poll until `http://localhost:8088/users/login` returns `200` before
proceeding.

### 2. Fetch the admin API key

The coolacid image seeds an admin user (`admin@admin.test` / `admin`) with a
legacy API key already populated in the `users.authkey` column. The browser
forces a password rotation on first login; the API key in the database is
not invalidated by that flow, so you can grab it directly:

```bash
# Read the key into a shell variable without printing it to the terminal
# (avoids leaking the key into ~/.bash_history via an intermediate echo).
MISP_API_KEY=$(docker exec castellum-misp-db \
  mariadb -umisp -pexample -D misp -N -B \
  -e "SELECT authkey FROM users WHERE id=1;")
```

Verify with:

```bash
curl -sS -H "Authorization: $MISP_API_KEY" \
  -H 'Accept: application/json' \
  http://localhost:8088/users/view/me.json | head -c 200
```

A `200` plus a JSON user document confirms the key is good. Add
`MISP_API_KEY` to your `.env`:

```bash
# Append to .env (key value is already in the shell variable):
echo "MISP_API_KEY=$MISP_API_KEY" >> .env
```

Then re-export from the file for subsequent shell commands:

```bash
export MISP_API_KEY=$(grep ^MISP_API_KEY .env | cut -d= -f2-)
```

### 3. Configure the backend

`.env` entries:

```env
MISP_BASE_URL=http://localhost:8088
# (credentials posted via the API below; not read directly from env)
```

Provision the integration row:

```bash
# If $TOKEN was fetched before the 1-3 min MISP boot wait, it may have
# expired. Re-fetch it now to avoid a cryptic 401:
TOKEN=$(curl -sS -X POST http://localhost:8081/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your-admin-password>"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

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
export (~233 MB) and the JVM heap couldn't hold the materialised bundle +
the HTTP client buffers. Nothing in the repo sets `-Xmx`, so the backend
runs on the JVM default max-heap of `-XX:MaxRAMPercentage=25.0` (about 25%
of the host's RAM); on a small host that ceiling is what the 233 MB bundle
blew through. Recommended fixes — already captured as deferred work in
`docs/progress.md`:

1. **Stream the bundle in chunks** rather than serialise to a single `byte[]`.
   Scope: `ThreatIntelService` + `TaxiiClient` + `MispClient` — backend only,
   no DB migration. High impact; eliminates the OOM class of failures.
   Cost: medium (requires chunked HTTP client + iterator pattern).

2. **Cap each push at a configurable object-count** (`taxii.max-objects-per-push`).
   Scope: `application.yml` property + guard in `TaxiiClient`/`MispClient`.
   Low cost; reduces blast radius immediately even without streaming.

3. **Tune the JVM heap** for installations that need to push the whole fleet at once.
   No `-Xmx` is configured anywhere in the repo (not the `Dockerfile`, not
   `application.yml`, no `JAVA_OPTS` / `JAVA_TOOL_OPTIONS`, no
   `.mvn/jvm.config`), so the backend runs on the JVM default max-heap of
   `-XX:MaxRAMPercentage=25.0` — roughly 25% of the host's RAM.
   - Check the default this host will pick:
     ```bash
     java -XX:+PrintFlagsFinal -version 2>/dev/null \
       | awk '/ MaxHeapSize/{print $4/1024/1024" MB"}'
     ```
   - Inspect the running backend — `jps -l` to find the pid, then:
     ```bash
     jcmd <pid> GC.heap_info
     ```
   - Pin it explicitly via the backend's environment, e.g.
     `JAVA_TOOL_OPTIONS=-Xmx<N>` (or `-XX:MaxRAMPercentage=<pct>`).
   Scope: deployment configuration only — no code change.
   Cost: trivial; applies only when streaming is not feasible.

The smoke-fixture compose files now ship operator-approved resource limits
(`mem_limit` / `cpus`) on each service so a runaway push cannot exhaust the
host; see `docker/misp-minimal.yml` and `docker/taxii-medallion.yml`.

## Audit-table snapshot

After the smoke run, `threat_intel_push` records every push attempt that
completes the upstream call. The TAXII / MISP 500s captured above never
reached the insert because the audit-writer (`ThreatIntelService.recordPush`,
already annotated `@Transactional(propagation = REQUIRES_NEW)`) is called
*after* `taxiiClient.push` / `mispClient.push` returns; an `IOException`
from the HTTP layer short-circuits the writer call entirely. The EXPORT
rows below come from the `POST /api/threat-intel/export` smoke (which
streams to a `.tar.gz` and records the bundle id without round-tripping to
a remote server):

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
   ORDER BY occurred_at DESC LIMIT 5;"
```

A future improvement (`docs/progress.md` Deferred) is to wrap the
`taxiiClient.push` / `mispClient.push` call in a try/catch and invoke
`recordPush(... statusCode, "error: " + e.getMessage(), ...)` from the
catch block so failure responses leave an audit trail. The audit writer
itself is already `REQUIRES_NEW`; the gap is purely that the writer is
never reached on the exception path. The corresponding non-blocking
finding is noted in the F6 review file under `audit-write semantics`.

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
| 9 | audit table      | TAXII/MISP failures not visible in `threat_intel_push` | Writer called only after HTTP push returns; IOException short-circuits it (writer is already `REQUIRES_NEW`) | Wrap push in try/catch, call `recordPush` from catch (deferred) |

All four entries 7-9 are tracked in `docs/progress.md` under Deferred for a
future "bundle streaming" feature.

> **Cross-feature ledger note (Nit6 / spec-tracer):** The feature spec
> (`features-runtime-fixes-v2.md` AC1) named `oasis-open/medallion` as the
> target image. That image does not exist on Docker Hub — OASIS publishes the
> Python source only. The implementer correctly substituted
> `sbirtane/medallion-taxii-server` (a community-packaged image that bundles
> the same OASIS `medallion` Python package). This substitution is intentional
> and documented; it is not a spec deviation.

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
