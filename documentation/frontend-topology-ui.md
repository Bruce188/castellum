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

Or use the top-bar scan trigger (currently scaffolded; scan execution itself is deferred).

## Acceptance evidence

- AC#1 — graph renders: `documentation/img/frontend-topology-ui-graph.png`
- AC#2 — node click opens detail panel: `documentation/img/frontend-topology-ui-detail.png`

Screenshots are captured manually after running both servers with demo data populated.

## Architecture

- **Risk to colour mapping** — `src/lib/riskTier.ts` derives a `RiskTier` (`low | med | high | crit | unknown`) from the composite score (`/api/risk/device/{id}`). Unknown when no CVE matches.
- **Edges** — derived client-side in `src/lib/subnetEdges.ts` by `/24` grouping. Star topology around the lowest-id device per subnet.
- **Polling** — `src/hooks/useScanStatus.ts` polls `/api/scans/{id}` every 5s, persists last id in `localStorage["castellum.lastScanId"]`, stops on terminal status.
- **Backend additions** — `GET /api/risk/device/{id}` returns `DeviceRiskDto{deviceId, score, topCveIds[]}`. CORS configured via `CorsConfig` for `http://localhost:5173`.

See `docs/analysis-v7.md` for full design rationale and open-question resolutions.
