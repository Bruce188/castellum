# frontend-topology-ui-graph.png — Capture Procedure

`documentation/img/frontend-topology-ui-graph.png` is currently a **1×1 transparent placeholder**. Replace it with a real screenshot of the full Cytoscape topology canvas using the procedure below.

## What the screenshot should show

The full Cytoscape topology canvas with at least 4 devices rendered, edges visible, and a non-trivial cose-bilkent layout (no overlapping nodes). Either tier-coloured nodes (low/med/high/crit) or a mix of risk states is preferred over an all-unknown canvas.

## Prerequisites

- Backend: `cd /home/bruce/projects/castellum/backend && ./mvnw spring-boot:run`
- Frontend: `cd /home/bruce/projects/castellum/frontend && npm run dev`
- PostgreSQL 16 running with seed data (>=4 devices, edges via subnet grouping or vuln matches).

## Capture commands

Browser-based capture (Chrome/Firefox built-in screenshot) is fastest. Or headless:

```bash
google-chrome --headless --disable-gpu --window-size=1280,720 \
  --screenshot=frontend-topology-ui-graph.png http://localhost:5173
```

## Install

```bash
cp frontend-topology-ui-graph.png /home/bruce/projects/castellum/documentation/img/frontend-topology-ui-graph.png
rm /home/bruce/projects/castellum/documentation/img/frontend-topology-ui-graph.png.TODO.md
```

See `documentation/frontend-topology-ui.html` Visual reference section for context.
