# frontend-topology-ui-detail.png — Capture Procedure

`documentation/img/frontend-topology-ui-detail.png` is currently a **1×1 transparent placeholder**. Replace it with a real screenshot of the `DeviceDetailPanel` open on a HIGH or CRIT-tier node using the procedure below.

## What the screenshot should show

The `DeviceDetailPanel` open on a HIGH or CRIT-tier node, showing:
- Risk score badge (numeric value visible — verifies AC#2 NaN guard)
- Services table populated with at least 2 rows (port/proto/name/version)
- "Top CVEs" section with at least 1 CVE row

## Prerequisites

Same as `frontend-topology-ui-graph.png.TODO.md`.

## Capture commands

1. Open `http://localhost:5173` in a browser.
2. Click a HIGH/CRIT-tier node to open the detail panel.
3. Use the browser's screenshot tool (Chrome devtools "Capture node screenshot" on the `<aside data-testid="device-detail-panel">` element gives the cleanest crop).
4. Save as `frontend-topology-ui-detail.png`.

## Install

```bash
cp frontend-topology-ui-detail.png /home/bruce/projects/castellum/documentation/img/frontend-topology-ui-detail.png
rm /home/bruce/projects/castellum/documentation/img/frontend-topology-ui-detail.png.TODO.md
```

See `documentation/frontend-topology-ui.html` Visual reference section for context.
