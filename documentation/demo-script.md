# Demo Script — Castellum 3-Minute Walkthrough

**Version:** 1.0 (Feature 10)
**Date:** 2026-04-29
**Duration target:** ~3 minutes (7 beats × ~25-30 seconds each)
**Recording status:** Script complete. Live recording is **deferred** — see [Recording procedure](#recording-procedure) below.

---

## Overview

This script covers the full AC #1 demo flow: scan a /24, passively discover devices, fingerprint an OT endpoint, score risk, compute the shortest exploit path, export a STIX bundle, and push it to MISP. Each beat has a visual cue (UI screen or curl command), a voice-over (~60-80 words), and on-screen overlay suggestions.

---

## Beat 1 — Scan (0:00–0:28)

**Visual cue:** Browser at `http://localhost:3000`. Navigate to the Scan panel. Show a `curl` terminal side-by-side.

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cidr": "10.0.1.0/24", "type": "PING_SWEEP"}'
# → {"id": 1}   HTTP 202 Accepted
```

**Voice-over:**
"Castellum kicks off an active scan with a single API call. We submit a PING_SWEEP against a /24 — Castellum hands off to nmap via a safe argument array, never a shell string, so there is no command injection surface. The 202 response gives us a scan ID. The controller requires ADMIN role — a VIEWER can read results but cannot initiate scans. Scan records and the initiating actor are immediately written to the append-only audit log."

**On-screen overlays:** `POST /api/scan` | `202 Accepted` | `ADMIN role required` | `Audit: SCAN_SUBMITTED`

---

## Beat 2 — Discover (0:28–0:56)

**Visual cue:** Topology graph panel loads. Nodes populate as passive discovery results arrive. Show ARP-discovered devices appearing as unlabelled nodes, then labels resolving via mDNS.

```bash
curl -X POST http://localhost:8080/api/discovery/passive \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0"}'
```

**Voice-over:**
"Alongside the active scan, passive discovery listens on the network interface using raw packet capture. ARP replies map MAC addresses to IPs. mDNS announcements resolve hostnames. LLDP and CDP frames identify vendor and port information for managed switches. This requires CAP_NET_RAW — no elevated container privilege, just the single raw-socket capability. Discovered devices appear in the topology graph in near real-time."

**On-screen overlays:** `CAP_NET_RAW (not --privileged)` | `ARP + mDNS + LLDP/CDP` | See [runtime-flags.md](runtime-flags.md)

---

## Beat 3 — Fingerprint (0:56–1:24)

**Visual cue:** Click a node in the topology graph labelled `10.0.1.42`. In the detail panel, show the OT probe result: `vendor: Schneider Electric`, `product: Modicon M340`, `version: 2.40`. Show the curl command in terminal.

```bash
curl -X POST http://localhost:8080/api/ot-probe \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host": "10.0.1.42", "port": 502, "protocol": "MODBUS_TCP"}'
# → {"vendor":"Schneider Electric","product":"Modicon M340","version":"2.40",...}
```

**Voice-over:**
"One device resolves as a Modbus/TCP endpoint on port 502 — an industrial PLC. Castellum probes it with a Modbus Function Code 43 Device Identification request: strictly read-only, no write function codes are ever sent. The host is validated as a dotted-quad IPv4 address — no DNS resolution — blocking SSRF. The fingerprint is written to the device and service tables automatically. For supported protocols and safety guarantees, see ot-probes.md."

**On-screen overlays:** `MODBUS_TCP :502` | `FC 43 Read-Only` | `SSRF guard: IPv4 only` | See [ot-probes.md](ot-probes.md)

---

## Beat 4 — Risk (1:24–1:52)

**Visual cue:** Risk score panel. Show the PLC device (`10.0.1.42`) with a CRITICAL badge and score of 9.8. Show a table of the top-5 at-risk devices. Terminal shows the risk query.

```bash
curl "http://localhost:8080/api/risk/score?cve=CVE-2021-22681&device=7" \
  -H "Authorization: Bearer $TOKEN"
# → {"cve":"CVE-2021-22681","deviceId":7,"score":9.8,"epss":0.71,
#    "inKev":true,"criticality":"CRITICAL","formula":"9.5×1.71×1.5×2/2"}
```

**Voice-over:**
"Castellum scores every CVE-device pair using four signals: CVSS base score, EPSS exploitation probability, CISA KEV membership, and the operator-assigned asset criticality. CVE-2021-22681 — a Rockwell Automation remote code execution — scores 9.8 on this CRITICAL-tier PLC: CVSS 9.5, EPSS 71%, listed in CISA KEV, CRITICAL asset. The composite scorer is a pure deterministic function — same inputs, same output, pinned by golden-file tests."

**On-screen overlays:** `CVSS × EPSS × KEV × Criticality` | `Score: 9.8 / 10` | `CISA KEV confirmed`

---

## Beat 5 — Graph (1:52–2:20)

**Visual cue:** Attack graph panel. Show a shortest-path query from a DMZ web server (`device 1`) to the PLC (`device 7`). The graph renders three hops with ATT&CK technique badges on edges.

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
"The attack graph shows the easiest exploit chain from the internet-facing web server to the OT PLC. Two hops: lateral movement via Remote Services (T1021) through a mid-tier host, then Exploit Public-Facing Application (T1190) against the PLC using CVE-2021-22681. Cumulative risk 9.8. The graph is built on demand by JGraphT — no cached state to poison. Each query is audited: who asked, from where to where, at what time."

**On-screen overlays:** `T1021 Lateral Movement` | `T1190 Initial Access` | `CVE-2021-22681` | `Cumulative risk: 9.8`

---

## Beat 6 — Export (2:20–2:46)

**Visual cue:** Threat Intel panel. Click "Export STIX Bundle." Show the returned JSON structure collapsed in the browser, then expand to show a `vulnerability` and an `indicator` STIX object.

```bash
curl -X POST http://localhost:8080/api/threat-intel/export \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
# → {"type":"bundle","id":"bundle--...","spec_version":"2.1",
#    "objects":[{"type":"vulnerability","name":"CVE-2021-22681",...},
#               {"type":"indicator","pattern":"..."},...]}
```

**Voice-over:**
"One POST produces a STIX 2.1 bundle containing vulnerability, indicator, and relationship objects for the entire at-risk inventory. This bundle is the machine-readable form of everything Castellum knows: what devices are present, which CVEs apply, and what risk scores were assigned. ADMIN role required. The export action is written to the threat_intel_push audit table with actor and timestamp. The bundle is ready to distribute."

**On-screen overlays:** `STIX 2.1 bundle` | `ADMIN required` | `Audit: THREAT_INTEL_EXPORTED`

---

## Beat 7 — MISP (2:46–3:00)

**Visual cue:** MISP UI (external browser tab). Show a new event appearing with Castellum-sourced attributes. Back in Castellum: show the push command and the 200 response.

```bash
curl -X POST http://localhost:8080/api/threat-intel/push/misp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
# → {"status":"pushed","mispEventId":"12345","attributesCreated":47}
```

**Voice-over:**
"One more call pushes the bundle directly to the MISP instance. Forty-seven attributes created: IP indicators, CVE references, risk tags. The MISP event is now shareable with partner organisations or an NCIRC-connected MISP federation. Castellum logs the push in the threat_intel_push audit table. From scan to shared intelligence: three minutes, zero manual data entry."

**On-screen overlays:** `POST /api/threat-intel/push/misp` | `47 attributes → MISP` | `NCIRC-compatible sharing`

---

## Recording Procedure

> **Status: Deferred.** Live recording is a post-pipeline follow-up. This script ships in Feature 10; the screen-captured GIF and video are out of scope for this iteration. See `documentation/img/demo.gif.TODO.md` for the capture procedure checklist.

When recording:

### Prerequisites

- Backend running: `cd backend && ./mvnw spring-boot:run`
- Frontend running: `cd frontend && npm run dev`
- PostgreSQL 16 running with seed data (at minimum: a /24 scan result, one OT device, one CVE match)
- MISP test instance accessible at `MISP_BASE_URL`
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
