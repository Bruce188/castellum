# Frontend Topology UI

Force-directed network topology visualizer for the Castellum REST API. Vite 8 + React 19.2 + TypeScript + Tailwind v4 + Cytoscape.js (cose-bilkent layout).

## Setup

### Backend

```bash
cd backend
cp .env.example .env
./mvnw spring-boot:run
```

Backend listens on `http://localhost:8080`.

### Frontend

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

Frontend listens on `http://localhost:5173`.

## Demo Data

The empty-database state shows a "no devices yet" notice. Populate via either route:

```bash
# Manual device insert
for i in 10 11 12 13; do
  curl -X POST http://localhost:8080/api/devices \
       -H 'content-type: application/json' \
       -d "{\"ipAddress\":\"192.168.1.$i\",\"hostname\":\"demo-$i\",\"criticality\":\"HIGH\"}"
done
```

Or use the in-page `ScanTriggerForm` on the topology landing — kicks off a scan without leaving the dashboard.

## Acceptance evidence

- AC#1 — graph renders: `documentation/img/frontend-topology-ui-graph.png`
- AC#2 — node click opens detail panel: `documentation/img/frontend-topology-ui-detail.png`

Screenshots are captured manually after running both servers with demo data populated.

## Routes

The SPA is wired through `react-router-dom` 7 in `src/App.tsx`. Authenticated sessions
mount the `AppShell` inside a `BrowserRouter`; an unauthenticated session short-circuits
to `<Login />`, and a first-login session short-circuits to `<ForcePasswordRotation />`
(no router is mounted in either short-circuit, so no `Route` can match).

The shell exposes seven top-level routes:

| Path | Page | Notes |
|------|------|-------|
| `/` | `TopologyPage` | Landing — `ScanTriggerForm` + force-directed graph + `DeviceDetailPanel`. |
| `/scans` | `ScansPage` | Scan history + status polling. |
| `/threats` | `ThreatsPage` | Risk leaderboard + per-CVE evidence + WhyScorePanel. |
| `/cves` | `CvesPage` | Paginated fleet CVE table with severity floor selector. |
| `/attack-graph` | `AttackGraphPage` | ADMIN-only render — `DevicePicker` + `TopologyView.highlightPath` overlay. |
| `/audit` | `AuditPage` | Audit timeline + CSV download. |
| `/settings` | `SettingsPage` | User management, scan policies, TAXII / MISP / STIX configuration. |

Active-state styling for the sidebar links is handled by `NavLink` from
`react-router-dom`; the canonical list lives in `src/components/Sidebar.tsx`. Each
link also exposes a native `title=` tooltip so the rail remains usable when
collapsed.

## Architecture

- **Risk to colour mapping** — `src/lib/riskTier.ts` derives a `RiskTier` (`low | med | high | crit | unknown`) from the composite score (`/api/risk/device/{id}`). Unknown when no CVE matches.
- **Edges** — derived client-side in `src/lib/subnetEdges.ts` by `/24` grouping. Star topology around the lowest-id device per subnet.
- **Polling** — `src/hooks/useScanStatus.ts` polls `/api/scans/{id}` every 5s, persists last id in `localStorage["castellum.lastScanId"]`, stops on terminal status.
- **Backend additions** — `GET /api/risk/device/{id}` returns `DeviceRiskDto{deviceId, score, topCveIds[]}`. CORS configured via `CorsConfig` for `http://localhost:5173`.

### Bounded retry wrapper

`src/api/client.ts` wraps every `fetch` in a single bounded retry. The transport
splits into two layers — `requestOnce<T>()` does one attempt and throws on non-OK
status, and `request<T>()` calls `requestOnce` once, then retries exactly once
on a narrow allow-list:

- `TypeError` — the browser surfaces network failures as `TypeError`.
- HTTP `502` / `503` / `504` — transient upstream, gateway, or timeout responses.

4xx responses (including `401`) are never retried. The 401 path inside
`requestOnce` clears the JWT and throws before the retry layer sees it, so the
"401 clears auth" contract is preserved end-to-end. Retry backoff is a fixed
~750 ms — chosen so the worst-case latency stays under 1.5 s. The retry layer
does not extend to `triggerScan`, `downloadAuditCsv`, `triggerInitialSync`, or
the file-blob endpoints; those use direct `fetch` calls because their
response-handling is bespoke.

### Empty-corpus banner scoping

The amber "threat intelligence feeds are empty" banner (`EmptyCorpusBanner`)
mounts inside `TopologyPage`, NOT inside `AppShell`. The mount point matters
because the banner polls `GET /api/risk/feeds/status` every 10 s while any of
`nvd.rowCount`, `epss.rowCount`, or `kev.entryCount` is 0. Mounting it under
the shell would fire the poll on every route. Mounting it under `TopologyPage`
scopes the poll lifecycle to the landing route — navigating to `/scans` or
`/audit` unmounts the banner and the `setInterval` is cleared by its cleanup
function.

The component also clears its own interval the moment all three feeds report
non-zero `rowCount`, inside the tick itself. The earlier shape relied on the
`if (!isEmpty(status)) return null` short-circuit to unmount the JSX, which
left `setInterval` firing for the life of the shell — the in-tick
`clearInterval` closes that gap.

See `docs/analysis-v7.md` for full design rationale and open-question resolutions.
