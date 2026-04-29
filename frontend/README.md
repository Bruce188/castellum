# Castellum Frontend

Vite + React 19 + TypeScript + Tailwind v4 + Cytoscape.js topology UI for the Castellum REST API.

## Setup

```bash
npm install
cp .env.example .env  # edit if backend is not on http://localhost:8080
```

## Scripts

| Command | Description |
|---|---|
| `npm run dev` | Vite dev server on `:5173` |
| `npm run build` | Type-check + production build to `dist/` |
| `npm run preview` | Preview the production build |
| `npm run lint` | ESLint |
| `npm run test` | Vitest run-once |

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `VITE_API_BASE_URL` | `http://localhost:8080` | Castellum REST API origin |

## Documentation

- [`../documentation/frontend-topology-ui.md`](../documentation/frontend-topology-ui.md) — feature overview, demo data, screenshot evidence
- [`../docs/analysis-v7.md`](../docs/analysis-v7.md) — design analysis and open-question resolutions
