# Demo Script — Castellum 3-Minute Walkthrough

**Version:** 1.0 (Feature 10)
**Date:** 2026-04-29
**Duration target:** ~3 minutes (7 beats × ~25-30 seconds each)
**Recording status:** Script complete. Live recording is **deferred** — see [Recording procedure](#recording-procedure) below.

---

## Overview

This script covers the full AC #1 demo flow: log in, navigate the sidebar, browse the
topology, drill into a device with inline edits, audit the actor trail, view threat
intelligence, browse the fleet CVE table, compute an attack path, and configure threat-intel
integrations to round out the picture. Each beat has a visual cue (UI screen or curl
command), a voice-over (~60-80 words), and on-screen overlay suggestions.

The flow follows the F5 sidebar nav — `/` (Topology) → `/audit` → `/threats` → `/cves` →
`/attack-graph` → `/settings` — so the demo can run entirely in the browser at
`http://localhost:5173`, with curl commands shown side-by-side only when it helps clarify
the underlying API contract.

---

## Beat 0 — Sign in (pre-roll)

**Visual cue:** Browser at `http://localhost:5173`. The login card sits centered on a gray
background — username (default `admin`) + password + "Sign in" button. After submit the
form auto-promotes a `mustChangePassword` user to the `ForcePasswordRotation` overlay
(first-login flow only); a normal session lands on the topology landing.

**Voice-over (optional pre-roll):**
"Sign in. Bcrypt cost 12 on the backend, JWT in `localStorage` on the frontend. First-login
users land on a forced-rotation overlay before the routed app mounts — no `BrowserRouter` is
mounted in that state, so no other route can match."

**On-screen overlays:** `POST /api/auth/login` | `BCrypt-12` | `first-login → ForcePasswordRotation`

---

## Beat 1 — Topology landing (0:00–0:28)

**Visual cue:** The sidebar shows seven nav links — Topology, Scans, Threats, CVEs, Attack
Graph, Audit, Settings. The Topology page is the landing route: a force-directed Cytoscape
graph in the middle, a `ScanTriggerForm` row above it, and (when feeds are empty) an amber
`EmptyCorpusBanner` at the top with a "Sync NVD + EPSS + KEV" button for ADMIN. Trigger a
ping-sweep against `10.0.1.0/24` from the form — nodes start to populate as scan results
land.

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cidr": "10.0.1.0/24", "type": "PING_SWEEP"}'
# → {"id": 1}   HTTP 202 Accepted
```

**Voice-over:**
"Castellum's topology landing is the operator's home base. The amber banner at the top
self-dismisses the moment all three threat-intel feeds are populated — its 10-second poll
is scoped to this route, not the whole app shell. The in-page `ScanTriggerForm` calls the
same `POST /api/scan` an `curl` would; ADMIN-only, scope-capped, rate-limited. Nodes are
coloured by composite risk tier — low, medium, high, critical, or unknown when no CVE matches."

**On-screen overlays:** `POST /api/scan` | `202 Accepted` | `ADMIN role required` | `EmptyCorpusBanner scoped to /`

---

## Beat 2 — Device detail + inline edits (0:28–0:56)

**Visual cue:** Click a node — the right-side `DeviceDetailPanel` slides in. It shows the
risk tier and composite score, an inline-editable `hostname` field, an inline-editable
`criticality` dropdown, and (for ADMIN) a `DecommissionButton` underneath. Edit hostname
from `demo-12` to `plc-front`; change criticality from `HIGH` to `CRITICAL`. Both fire
`PUT /api/devices/{id}` and refetch the device list so the graph stays consistent. Below
the device block, the `CveEvidenceTable` shows the top CVEs, and the `WhyScorePanel`
breaks the composite score into its CVSS × EPSS × KEV × Criticality components.

```bash
curl -X PUT http://localhost:8080/api/devices/12 \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"ipAddress":"10.0.1.12","hostname":"plc-front","criticality":"CRITICAL", ...}'
```

**Voice-over:**
"Click any node to open the detail panel. Hostname and criticality are inline-editable for
ADMIN — pencil icon, click, save. Decommission button just below — soft-deletes the device
from the active graph. The CVE evidence table and 'why this score' panel are right there in
the same drawer; no extra navigation."

**On-screen overlays:** `PUT /api/devices/{id}` | `inline-edit (ADMIN)` | `WhyScorePanel: CVSS×EPSS×KEV×Criticality`

---

## Beat 3 — Audit trail (0:56–1:24)

**Visual cue:** Click `Audit` in the sidebar. The `AuditLogPanel` renders — filterable
table of events with actor, resource, timestamp. Filter on `actor=admin` and
`eventType=DEVICE_UPDATED`; the two PUTs from Beat 2 are right at the top. Click the CSV
download button — `GET /api/audit/csv` returns a 413 with `filteredCount` + `limit` if the
cap is exceeded, otherwise a streamed file.

```bash
curl "http://localhost:8080/api/audit/csv?actor=admin" \
  -H "Authorization: Bearer $TOKEN" -o audit.csv
```

**Voice-over:**
"The audit log is append-only — backend-enforced via a read-only repository fragment, so
even an admin with database credentials cannot delete a row through the JPA layer. Every
mutating action — scan submitted, device updated, password changed, integration pushed —
shows up here, with actor and timestamp. CSV export is gated at twenty-five thousand rows;
filter first, then download."

**On-screen overlays:** `GET /api/audit` | `append-only (no DELETE)` | `CSV cap: filteredCount/limit`

---

## Beat 4 — Threats dashboard (1:24–1:52)

**Visual cue:** Click `Threats`. `ThreatsDashboard` shows the top-N at-risk leaderboard.
The PLC at `10.0.1.42` sits at the top with a 9.8 composite. Click into its row — the
`CveEvidenceTable` expands and the `WhyScorePanel` shows the formula breakdown.

```bash
curl "http://localhost:8080/api/risk/top?n=10" \
  -H "Authorization: Bearer $TOKEN"
# → [ { "deviceId": 7, "ipAddress": "10.0.1.42", "score": 9.80, ... }, ... ]
```

**Voice-over:**
"The threats dashboard surfaces the top-N at-risk devices fleet-wide. Composite scores fold
in CVSS base, EPSS exploitation probability, CISA KEV membership, and operator-assigned
criticality. CVE-2021-22681 — a Rockwell Automation RCE — pushes this PLC to 9.8. CVSS 9.5,
EPSS 71%, KEV-listed, asset criticality CRITICAL. Pure deterministic scoring, pinned by
golden-file tests; same inputs always produce the same output."

**On-screen overlays:** `CVSS × EPSS × KEV × Criticality` | `Score: 9.80 / 10` | `CISA KEV confirmed`

---

## Beat 5 — Fleet CVE table (1:52–2:08)

**Visual cue:** Click `CVEs`. The page shows a paginated table — CVE ID, CVSS v3.1, short
description, last-modified date. The header includes a "severity floor" selector (`all`,
`high ≥ 7.0`, `critical ≥ 9.0`) and a refresh button. Switch the floor to `critical`; the
page resets to 0 and the table re-queries with `minScore=9.0`. Pagination buttons at the
bottom show "Page N of M".

```bash
curl "http://localhost:8080/api/cve/fleet?page=0&size=25&minScore=9.0" \
  -H "Authorization: Bearer $TOKEN"
```

**Voice-over:**
"The CVEs page is the fleet-wide CVE listing — every CVE that matched at least one device
in the catalog. The severity floor lets the operator narrow to the truly urgent ones; the
table re-queries server-side rather than filtering in the browser, which keeps the page
responsive on a fleet of tens of thousands. The endpoint is backed by a partial index on
`cvss_v31_score` so the listing stays fast."

**On-screen overlays:** `GET /api/cve/fleet` | `severity floor: all / ≥7.0 / ≥9.0` | `partial index on cvss_v31_score`

---

## Beat 6 — Attack graph (2:08–2:36)

**Visual cue:** Click `Attack Graph`. The page is ADMIN-only — VIEWERs land on a notice
explaining the restriction. As an ADMIN, two `DevicePicker` combo boxes appear, autocomplete
by hostname or IP, capped at 50 entries per dropdown. Pick `dmz-web-1` as the source and
`plc-front` (the PLC from Beat 2) as the target; click "Compute path". The right pane —
the same `TopologyView` used on the landing route — overlays the shortest path with the
`path-highlight` class (red ring on nodes, dashed red stroke on edges). The left pane
renders a numbered breakdown — one step per hop with edge type, CVE id, and ATT&CK
technique surfaced.

```bash
curl "http://localhost:8080/api/graph/shortest-path?from=1&to=7" \
  -H "Authorization: Bearer $TOKEN"
# → {"from":1,"to":7,"hops":[
#     {"deviceId":1,...},
#     {"deviceId":3,"edgeType":"SAME_SUBNET","attackTechniqueId":"T1021",...},
#     {"deviceId":7,"edgeType":"EXPLOITABLE_VULN","attackTechniqueId":"T1190",
#      "cveId":"CVE-2021-22681","edgeRisk":9.8,"cumulativeRisk":9.8}
#   ],"pathFound":true}
```

**Voice-over:**
"The attack graph computes the easiest exploit chain between two devices. JGraphT Dijkstra
under the hood — edges are weighted by composite risk, so lower-cost paths are the ones an
attacker would actually take. T1021 Remote Services for lateral movement, then T1190
Exploit Public-Facing Application against the PLC using CVE-2021-22681. Cumulative risk
9.8. The graph is built on demand — no cached state to poison — and the build is bounded by
a max-device cap that returns a 503 if the operator tries to graph an unreasonably large
fleet."

**On-screen overlays:** `ADMIN only` | `T1021 + T1190` | `CVE-2021-22681` | `Cumulative risk: 9.8`

---

## Beat 7 — Settings: integrations + STIX export (2:36–3:00)

**Visual cue:** Click `Settings`. The page hosts `UserManagementPanel` (ADMIN-only — list /
create users, change roles, disable accounts), `ScanPolicyPanel` (create / enable / disable
/ delete cron-driven scan policies, the V14 surface), `TaxiiConfigPanel` and
`MispConfigPanel` (PUT credentials to `POST /api/integrations/{type}`, AES-256-GCM
encrypted server-side via `AesGcmCipher`), and `StixExportPanel`. Click "Download STIX
bundle" — the panel calls `POST /api/threat-intel/export`, a `Blob` comes back, the panel
spawns an anchor with `download="castellum-stix-bundle.json"`, clicks it programmatically,
then revokes the object URL. The status row underneath confirms the download.

```bash
curl -X POST http://localhost:8080/api/threat-intel/export \
  -H "Authorization: Bearer $TOKEN" -o castellum-stix-bundle.json
# → {"type":"bundle","id":"bundle--...","spec_version":"2.1", "objects":[...]}
```

**Voice-over:**
"Settings is the admin surface — user management, scan-policy schedules, threat-intel
integrations, STIX export. Integration credentials are encrypted at rest with AES-256-GCM,
key sourced from `CASTELLUM_INTEGRATION_KEY`. Cipher is 12-byte IV plus 128-bit GCM tag.
One click on STIX export streams a STIX 2.1 bundle straight to disk — vulnerability,
indicator, and relationship objects covering the entire at-risk inventory. The export is
audited; actor and timestamp are in the audit log we saw at Beat 3."

**On-screen overlays:** `AES-256-GCM (12B IV + 128b tag)` | `POST /api/threat-intel/export` | `Audit: STIX_EXPORTED`

---

## Recording Procedure

> **Status: Deferred.** Live recording is a post-pipeline follow-up. This script ships in Feature 10; the screen-captured GIF and video are out of scope for this iteration. See `documentation/img/demo.gif.TODO.md` for the capture procedure checklist.

When recording:

### Prerequisites

- Backend running: `cd backend && ./mvnw spring-boot:run`
- Frontend running: `cd frontend && npm run dev`
- PostgreSQL 16 running with seed data (at minimum: a /24 scan result, one OT device, one CVE match)
- TAXII / MISP test instances accessible if exercising Beat 7 push surfaces
- OBS Studio installed, audio input configured for voice-over
- Terminal with `TOKEN` variable set (obtain via `POST /api/auth/login`)

### Recording steps

1. Start OBS. Configure a scene with: browser window (Castellum frontend) + terminal side-by-side.
2. Start recording. Narrate each beat from this script. Target 25–30 seconds per beat.
3. Total target: 3 minutes. Allow up to 3:30 for natural pacing.
4. Stop recording. Export as MP4 (H.264, 1920×1080 or 1280×720).

### Converting MP4 to GIF

```bash
# Step 1: generate optimised palette from the video:
ffmpeg -i demo.mp4 -vf "fps=12,scale=960:-1:flags=lanczos,palettegen" -y palette.png

# Step 2: render GIF using the palette:
ffmpeg -i demo.mp4 -i palette.png \
  -lavfi "fps=12,scale=960:-1:flags=lanczos [x]; [x][1:v] paletteuse" \
  -y demo.gif
```

**Size target: ≤ 3 MB.** If the output exceeds 3 MB, reduce fps to 10 and scale width to 720:

```bash
ffmpeg -i demo.mp4 -vf "fps=10,scale=720:-1:flags=lanczos,palettegen" -y palette.png
ffmpeg -i demo.mp4 -i palette.png \
  -lavfi "fps=10,scale=720:-1:flags=lanczos [x]; [x][1:v] paletteuse" \
  -y demo.gif
```

Place the final `demo.gif` at `documentation/img/demo.gif` (replacing the placeholder).

### Verify size

```bash
stat -c %s documentation/img/demo.gif
# Must be ≤ 3145728 (3 MB)
```
