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

## Attack Graph

Castellum builds an in-process attack graph (JGraphT `DefaultDirectedWeightedGraph` + `DijkstraShortestPath`) on each query and returns the easiest exploit chain between two devices the inventory already knows about. This is a defender-side artifact: "an attacker who lands on host A reaches host B via this ordered hop sequence, with this much risk accumulating along the way." Each hop is annotated with the MITRE ATT&CK technique an attacker would conceptually be using on that edge.

### Endpoint

```
GET /api/graph/shortest-path?from={deviceA}&to={deviceB}
```

Example response:

```json
{
  "from": 1,
  "to": 5,
  "hops": [
    { "deviceId": 1, "ipAddress": "10.0.0.10", "edgeType": null, "attackTechniqueId": null, "attackTechniqueName": null, "edgeRisk": 0.00, "cumulativeRisk": 0.00, "cveId": null },
    { "deviceId": 3, "ipAddress": "10.0.0.42", "edgeType": "SAME_SUBNET", "attackTechniqueId": "T1021", "attackTechniqueName": "Remote Services", "edgeRisk": 0.00, "cumulativeRisk": 0.00, "cveId": null },
    { "deviceId": 5, "ipAddress": "10.0.0.99", "edgeType": "EXPLOITABLE_VULN", "attackTechniqueId": "T1190", "attackTechniqueName": "Exploit Public-Facing Application", "edgeRisk": 9.50, "cumulativeRisk": 9.50, "cveId": "CVE-2020-15778" }
  ],
  "totalHops": 2,
  "cumulativeRisk": 9.50,
  "pathFound": true
}
```

The first hop in `hops` is the source vertex (edge fields null). Subsequent hops carry the destination of each traversed edge plus edge metadata. `cveId` is populated only on `EXPLOITABLE_VULN` hops. No-path responses return 200 with `pathFound: false` and an empty `hops` array — defenders asking about reachability deserve a structured "no" rather than a 404. Reserved 404 status: `from` or `to` deviceId not in the inventory.

### Edge types and ATT&CK mapping

| Edge type | ATT&CK ID | Technique | Tactic |
|-----------|-----------|-----------|--------|
| `SAME_SUBNET` | T1021 | Remote Services | Lateral Movement |
| `EXPLOITABLE_VULN` | T1190 | Exploit Public-Facing Application | Initial Access |
| `WEAK_CRED_PATH` | T1078 | Valid Accounts | Initial Access / Lateral Movement |

The mapping is a published contract — encoded in `io.castellum.graph.AttackTechniqueMapper`. Changing it requires a source edit, recompile, and golden-test refresh.

### Configuration

| Key | Default | Purpose |
|-----|---------|---------|
| `castellum.graph.subnet-cap` (`GRAPH_SUBNET_CAP`) | 64 | Maximum devices per /24 before SAME_SUBNET edges are skipped (memory bound). |
| `castellum.graph.vulns-per-pair-cap` (`GRAPH_VULNS_PER_PAIR_CAP`) | 5 | Maximum number of EXPLOITABLE_VULN edges retained per (source-peer, target) pair. |

### Limitations (v1)

- **Rebuild on each query.** Acceptable at MVP scale (≤10k devices); P50 < 500 ms / P99 < 2 s budget. Caching is a follow-up.
- **IPv6 SAME_SUBNET grouping not handled.** Non-IPv4 IPs are excluded from SAME_SUBNET edges; queries between IPv6-only devices return `pathFound: false` unless an EXPLOITABLE_VULN edge exists.
- **Lossy `service.name` → CPE mapping.** `name.toLowerCase().replaceAll("[^a-z0-9_-]", "")` is applied for both vendor and product. Services with hyphenated branding (`OpenSSH-Server`) may miss CVE matches against the canonical `openssh` CPE.
- **WEAK_CRED_PATH edges are typed-but-empty.** v1 emits zero edges; the seam exists for future credential-spray detector wiring.
- **Single technique for all vuln edges.** EXPLOITABLE_VULN → T1190. SMB/RPC/RDP-specific T1210 mapping is a follow-up.
- **One audit_log row per query.** Every successful and no-path query is recorded with `{from, to, totalHops, cumulativeRisk}`.

### Licensing note

JGraphT 1.5.2 is dual-licensed EPL-2.0 / LGPL-2.1. Castellum distributes under Apache-2.0 using the EPL-2.0 path.

## OT/ICS Read-Only Fingerprinters

Castellum can fingerprint OT/ICS devices using read-only protocol requests. No write commands are
ever issued. Supported protocols: Modbus/TCP, DNP3, S7comm, BACnet/IP.

See [documentation/ot-probes.md](documentation/ot-probes.md) for the full reference.

### Endpoint

```
POST /api/ot-probe
Content-Type: application/json

{ "host": "192.168.1.10", "port": 502, "protocol": "MODBUS_TCP" }
```

`host` must be a dotted-quad IPv4 address — hostnames are rejected by the SSRF guard.
Protocols: `MODBUS_TCP` (502), `DNP3` (20000), `S7COMM` (102), `BACNET_IP` (47808).

On success (HTTP 200) the response includes `vendor`, `product`, `version`, `rawFields`, `deviceId`,
`serviceId`, and `observedAt`. The device and service rows in the database are upserted automatically.

### Configuration

| Key | Default | Env var |
|-----|---------|---------|
| `castellum.ot.probe.connect-timeout-ms` | 3000 | `OT_PROBE_CONNECT_TIMEOUT_MS` |
| `castellum.ot.probe.read-timeout-ms` | 5000 | `OT_PROBE_READ_TIMEOUT_MS` |
| `castellum.ot.probe.total-timeout-ms` | 10000 | `OT_PROBE_TOTAL_TIMEOUT_MS` |
| `castellum.ot.probe.max-concurrent` | 8 | `OT_PROBE_MAX_CONCURRENT` |

## License

Apache License 2.0 — see [LICENSE](LICENSE).
