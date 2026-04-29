# Castellum

NATO-track network topology and vulnerability mapper. Backend in Spring Boot 3.5.13 (Java 21, virtual threads), PostgreSQL 16 + Flyway, frontend in Vite + React + TypeScript. License: Apache-2.0.

## Status

Week 2 of build. Backend scaffold (REST CRUD, hardened `NmapRunner`, audit log) and local NVD CVE mirror (V5 schema, sync orchestrator, CPE→CVE matcher) are in place. Auth, distroless container, SBOM, and signing land in feat/security-hardening-and-supply-chain. README will be rewritten leading with threat model in docs/threat-model-and-nato-docs.

## NVD CVE Mirror

Castellum maintains a local mirror of the NVD CVE corpus to eliminate per-scan API rate-limit dependency. Scan-time CPE→CVE matching reads the local `cve` + `cve_cpe_match` tables only — no live NVD calls on the hot path.

The mirror is built via the NVD 2.0 REST API (`https://services.nvd.nist.gov/rest/json/cves/2.0`). The legacy JSON 1.1 feeds were deprecated by NIST in December 2023 and are NOT used.

### Throughput

- **Anonymous** (no API key): 5 requests / 30 seconds. The client sleeps ≥6 seconds between requests.
- **With API key** (registration deferred): 50 requests / 30 seconds.

First-run bulk pull of the full ~250k-CVE history:
- Anonymous: ~3–4 hours.
- With key: ~30 minutes.

### Bulk sync

```
./scripts/nvd-bulk-sync.sh --since 2026-04-01
./scripts/nvd-bulk-sync.sh --since 2026-04-01 --until 2026-04-29
./scripts/nvd-bulk-sync.sh --since 2026-04-01 --api-key YOUR_KEY
```

### Daily incremental

Run with no `--since` to invoke `incrementalPull()`, which uses `MAX(last_modified)` from the local `cve` table as the cursor:

```
./scripts/nvd-bulk-sync.sh
```

Against an up-to-date mirror, the incremental completes in under one minute.

## Important: `AWAITING ANALYSIS` Enrichment Lag

Newly-published CVEs may carry `vulnStatus = "Awaiting Analysis"` for hours-to-days while NVD analysts add CVSS scores and CPE applicability data.

The mirror reflects whatever NVD has at sync time. CVEs in the `Awaiting Analysis` state WILL appear in the local `cve` table, but their `cvss_v31_score` and `cve_cpe_match` rows may be empty until NVD finishes enrichment. Re-running the daily incremental picks up the enrichment when NVD publishes it.

This is a property of the NVD data pipeline, not a Castellum bug. The CVE→CPE matcher will simply return no matches for an unenriched CVE; it does not fall back to the live NVD API to fetch enrichment on demand (per the no-live-call-on-hot-path constraint).

## API

### CVE Mirror

- `GET /api/cve/{cveId}` — retrieve a single CVE from the local mirror; 404 if not present.
- `GET /api/cve?cpe=cpe:2.3:...` — list CVEs matching the given CPE 2.3 URI using range-aware matching.

### Scans

- `POST /api/scan` — submit a scan request (body: `{"cidr": "...", "type": "PING_SWEEP"}`); returns `{"id": N}` with HTTP 202.
- `GET /api/scans/{id}` — retrieve a scan by ID.
- `GET /api/scans` — list scans (paginated; default page size 100).

### Devices and Services

- `GET /api/devices`, `POST /api/devices`, `GET /api/devices/{id}`, `DELETE /api/devices/{id}`
- `GET /api/network-services`, `POST /api/network-services`, `DELETE /api/network-services/{id}`

## License

Apache License 2.0 — see [LICENSE](LICENSE).
