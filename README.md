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

## Risk Scoring

Castellum combines four signals to produce a composite risk score in the range `[0, 10]` for any `(CVE, Device)` pair.

### Formula

```
score = clamp(CVSS_on_ten × (1 + EPSS_WEIGHT×EPSS) × kevMult × critMult / (1 + CRIT_CRITICAL), 0, 10)
```

where:
- `CVSS_on_ten` = CVSS base score (v3.1 preferred, fallback to v3.0 → v2 → 0.0), scaled to 0–10
- `EPSS_WEIGHT = 1.0` — an EPSS probability of 1.0 doubles the CVSS contribution
- `kevMult = 1.5` if the CVE is in the CISA KEV catalog, else `1.0` — known active exploitation adds a 50 % uplift
- `critMult = 1 + critFactor` where `critFactor ∈ {LOW: 0.0, MEDIUM: 0.25, HIGH: 0.5, CRITICAL: 1.0}`
- The divisor `(1 + CRIT_CRITICAL) = 2.0` normalises the scale so that max-CVSS + CRITICAL asset (no other signals) lands exactly at 10.00

Plain-English summary: a CVE listed in CISA KEV is multiplied by 1.5× to reflect known active exploitation; an EPSS probability of 1.0 doubles the CVSS contribution; asset criticality scales the score from 1× (LOW) to 2× (CRITICAL), divided by 2 to keep the ceiling at 10.

### Signal Sources

| Signal | Source | Refresh |
|--------|--------|---------|
| EPSS daily probabilities | `https://epss.cyentia.com/epss_scores-current.csv.gz` | Daily at 06:00 UTC |
| CISA KEV catalog | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Daily at 06:00 UTC |
| CVSS scores | Local NVD mirror (`cve` table) | NVD incremental sync |
| Asset criticality | `device.criticality` column | Set per-device via `PUT /api/devices/{id}` |

### Refresh Cadence

Both EPSS and KEV feeds are fetched daily at 06:00 UTC by `RiskFeedScheduler`. The cron expression defaults to `0 0 6 * * *` and can be overridden via `RISK_REFRESH_CRON`.

EPSS uses a **snapshot-replace** strategy: each daily run deletes all existing `epss_score` rows and bulk-inserts the fresh feed. KEV uses **upsert-on-`cve_id`** so re-runs are idempotent.

### Determinism Contract

`CompositeScorer.score(RiskInputs)` is a **pure function** — same inputs always produce the same output. It has no database access, no HTTP calls, no clock, and no random state. All formula constants are `private static final` hard-coded inside `CompositeScorer`; they cannot be changed via configuration. Golden-file tests in `src/test/resources/risk/golden/` pin known input tuples to expected scores (tolerance ±0.01).

### REST Endpoints

- `GET /api/risk/score?cve=CVE-YYYY-NNNNN&device=42` — composite score for a `(CVE, Device)` pair
- `GET /api/risk/feeds/status` — freshness: EPSS row count + latest score date, KEV entry count + last ingestion timestamp

### Operations Runbook

**`Device.criticality` defaults to `MEDIUM` for all existing devices.** The V6 migration sets `DEFAULT 'MEDIUM'` on the `criticality` column, so every existing row is assigned `MEDIUM` (multiplier 1.25×) automatically. Operators should review the device inventory and update the criticality for known-critical assets:

```
PUT /api/devices/{id}
{"ipAddress": "10.0.0.1", "criticality": "CRITICAL"}
```

Valid values: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. Until updated, all devices score with the MEDIUM (`1.25×`) multiplier.

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
