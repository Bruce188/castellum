# Threat Model — Castellum

**Version:** 1.0 (Feature 10)
**Date:** 2026-04-29
**Scope:** All eleven modules of the Castellum backend plus the React frontend.
**Methodology:** STRIDE-per-element applied per module.

---

## Executive Summary

Castellum is an operational defender tool: it scans networks, discovers devices, fingerprints OT/ICS equipment, enriches findings with CVE/EPSS/KEV data, computes composite risk scores, builds attack graphs, and exports threat intelligence to MISP or TAXII. It is deployed by security operators inside a controlled network segment and accessed by a small, identified set of users.

The primary assets are the device inventory, the CVE enrichment data, the risk scores, and the threat-intelligence bundles produced for export. The most sensitive operational secrets are the JWT signing key and the admin password hash.

The in-scope adversary is a network-adjacent attacker who can reach the API over HTTP and a web browser that navigates to the frontend. Nation-state supply-chain compromise, insider threat with root access, physical hardware attacks, and side-channel analysis are explicitly out of scope for this version.

Key operational concerns:

1. **Scan amplification** — Castellum drives nmap subprocess calls against external hosts. Misconfiguration or injection could weaponise the scanner.
2. **OT safety** — the OT/ICS probe modules interact with live operational technology. A bug that issues write-mode commands to a PLC is a safety event, not merely a security incident.
3. **Audit integrity** — Castellum is its own evidence store. Tampering with the audit log undermines all forensic value.
4. **Credential theft** — the JWT secret and admin hash are high-value targets; their compromise escalates an observer to full admin.
5. **Egress trust** — Castellum calls NVD, EPSS, CISA, and MISP/TAXII. A compromised upstream feed or SSRF vulnerability can introduce malicious data or exfiltrate inventory.

Full mitigations are listed in the [Top-5 mitigations](#top-5-mitigations) section. See also:
- [documentation/auth.md](auth.md) — RBAC matrix, JWT contract, bootstrap admin
- [documentation/supply-chain.md](supply-chain.md) — distroless, Trivy gate, SBOM
- [documentation/ot-probes.md](ot-probes.md) — read-only OT contract
- [documentation/runtime-flags.md](runtime-flags.md) — CAP_NET_RAW, pcap4j JVM flags
- [documentation/stix-taxii-misp.md](stix-taxii-misp.md) — export audit trail
- [documentation/frontend-topology-ui.md](frontend-topology-ui.md) — UI architecture

---

## Asset Inventory

| Module | Data assets | Secret assets | Identity assets | Network paths |
|--------|------------|---------------|-----------------|---------------|
| Active scanner | Scan records, discovered hosts | None | Operator identity initiating scan | Castellum → target CIDR (TCP/ICMP) |
| Passive discovery | ARP cache, mDNS announcements, raw frames | None | None | NIC → JVM via libpcap (CAP_NET_RAW) |
| Threat-intel ingest | CVE corpus (~250k records), EPSS scores, KEV list | `CASTELLUM_NVD_API_KEY` | NVD API identity | Castellum → NVD/EPSS/CISA (egress HTTPS) |
| Risk scorer | Composite risk scores, per-device criticality | None | None | In-process pure function |
| Attack graph | Reachability data (who can reach whom via what CVE) | None | None | In-process (JGraphT); query results via REST |
| OT/ICS probes | Vendor/product/version fingerprint per OT host | None | Operator identity | Castellum → OT network segment (TCP read-only) |
| Threat-intel export | STIX 2.1 bundles, TAXII push records, MISP event IDs | `TAXII_USERNAME`/`TAXII_PASSWORD`, `MISP_API_KEY` | TAXII/MISP partner identity | Castellum → TAXII/MISP (egress HTTPS) |
| Auth/RBAC | User table, role assignments, active sessions | `CASTELLUM_SECURITY_JWT_SECRET`, `CASTELLUM_ADMIN_PASSWORD_HASH` | Admin and Viewer principals | External → API (login endpoint) |
| Audit log | All mutating-operation records, actor/action/resource | None | All authenticated actors | In-process → Postgres `audit_log` table |
| REST API surface | All API request/response data | None | All authenticated actors | External HTTP → service layer |
| Frontend | Session token (localStorage), UI state | Session JWT | Browser-side user identity | Browser → API (HTTP/HTTPS) |

---

## Trust-Boundary Diagram

```
                          ┌─────────────────────────────────────────────────────┐
  External network        │                  Castellum JVM                       │
  (operator browser)      │                                                       │
        │                 │  ┌──────────┐  ┌──────────┐  ┌─────────────────┐    │
        │  HTTP/HTTPS ─── │──▶  REST API │──▶  Service │──▶   PostgreSQL 16  │   │
        │                 │  │ layer     │  │  layer   │  │  (inventory,    │   │
        │                 │  │(controllers)│  │(scan,risk│  │   audit_log,   │   │
        │                 │  │          │  │ graph,   │  │   cve, epss,   │   │
        │                 │  └──────────┘  │ auth…)   │  │   device…)     │   │
        │                 │                └──────────┘  └─────────────────┘    │
        │                 │                                                       │
        │                 │  ┌──────────────────────────────────────────────┐    │
        │                 │  │  NIC (CAP_NET_RAW — passive discovery only)   │    │
        │                 │  │  PcapSniffer / ArpCacheReader / MdnsProbe    │    │
        │                 │  └──────────────────────────────────────────────┘    │
        │                 └─────────────────────────────────────────────────────┘
        │
        │  Egress HTTPS (TLS at reverse proxy)
        ├──────────────────────────────── NVD (nvd.nist.gov)
        ├──────────────────────────────── EPSS (epss.cyentia.com)
        ├──────────────────────────────── CISA KEV (cisa.gov)
        ├──────────────────────────────── TAXII partner
        └──────────────────────────────── MISP instance

  OT network segment (read-only TCP probes)
        │
        ├──── Modbus/TCP :502
        ├──── DNP3 :20000
        ├──── S7comm :102
        └──── BACnet/IP :47808

  nmap subprocess (exec from JVM — argv-only, no shell)
        └──── Target CIDR / hosts (PING_SWEEP)
```

Trust boundaries in order of sensitivity:

1. **External → API** — primary attack surface; JWT authentication required.
2. **NIC → JVM** — CAP_NET_RAW grants raw packet capture; must be strictly scoped.
3. **JVM → OT network** — read-only TCP; function-code whitelist enforced.
4. **Castellum → NVD/EPSS/CISA** — egress; data integrity concern (feed tampering).
5. **Castellum → TAXII/MISP** — egress; credential and data confidentiality.
6. **JVM → Postgres** — internal; append-only for audit log.
7. **JVM → nmap subprocess** — OS exec boundary; argv injection prevention critical.

---

## Per-Module STRIDE Matrices

### Module 1 — Active Scanner

Package: `scan/NmapRunner`, `scan/CidrValidator`, `web/ScanController`
Trust boundary: Castellum JVM → external network (nmap subprocess execution)

**S — Spoofing**
The scan is initiated via `POST /api/scan` which requires the `ADMIN` role. A spoofed identity could submit a scan request only if they can forge or steal a valid JWT. The ADMIN role gate and JWT HMAC-SHA256 verification in `security/JwtAuthenticationFilter` provide the primary control. Mitigation: use a strong JWT secret (≥ 32 bytes) and short token TTL (1 h default).

**T — Tampering**
`CidrValidator` enforces that the CIDR is a valid IP range and rejects RFC-1918 ranges when the operator disables private-range scanning. The nmap subprocess is constructed using an argument array, never via shell string interpolation, preventing command-injection via CIDR input. If the argument array construction in `NmapRunner` were changed to string concatenation, injection would be possible — this invariant must be maintained. Automated validation: `NmapRunnerTest` covers whitespace/semicolon injection patterns.

**R — Repudiation**
Every `POST /api/scan` triggers an `AuditService.recordEvent` call with actor, action `SCAN_SUBMITTED`, CIDR, and timestamp. Repudiation is contained by the append-only audit log. An operator who claims they did not submit a scan can be refuted by the audit record.

**I — Information Disclosure**
Scan results (discovered hosts, open ports, service banners) are stored in the device and network-service tables and returned to any `VIEWER`+ authenticated user. An over-privileged viewer can enumerate the full network topology. At MVP scale, all authenticated users share the same inventory view — fine-grained per-CIDR ACLs are out of scope for v1.

**D — Denial of Service**
An ADMIN could submit a scan against a large CIDR (e.g. /16) repeatedly, consuming NIC bandwidth and CPU. No per-user rate limiting exists in v1 (see AC-7 compliance non-claim in [documentation/compliance.md](compliance.md)). Mitigation at v1: ADMIN role gate reduces the blast radius; operator-level rate limiting at the reverse proxy is recommended.

**E — Elevation of Privilege**
The scan controller enforces `ADMIN` only for scan submission. A VIEWER cannot submit scans. If a future refactor degrades the `hasRole('ADMIN')` expression to `hasAnyRole`, VIEWERs would gain scan submission rights — code review must verify the `@PreAuthorize` annotation is not weakened.

---

### Module 2 — Passive Discovery

Package: `discovery/` — `PcapSniffer`, `ArpCacheReader`, `MdnsProbe`, `LldpDecoder`, `CdpDecoder`
Trust boundary: physical NIC → JVM via CAP_NET_RAW / libpcap JNA

**S — Spoofing**
ARP spoofing by a device on the monitored segment causes Castellum to record incorrect MAC-to-IP mappings in the device table. This is an environmental threat, not a Castellum implementation flaw, but its impact is inventory poisoning. Mitigation: correlate ARP observations with mDNS and LLDP/CDP to cross-validate identity claims.

**T — Tampering**
A rogue device injecting crafted mDNS or LLDP frames could insert false service records into the Castellum inventory. `LldpDecoder` and `CdpDecoder` parse TLV frames directly; malformed or oversized TLVs must be rejected rather than heap-allocated verbatim. Current parsers should enforce maximum TLV length limits.

**R — Repudiation**
Passive discovery events are not individually audited (no `AuditService.recordEvent` per frame captured). An operator cannot retroactively determine which specific frame caused a device row to be created. Enhancement opportunity: log the triggering source (ARP/mDNS/LLDP) per device-creation event.

**I — Information Disclosure**
The CAP_NET_RAW capability grants the JVM ability to read all frames on the interface, including frames unrelated to Castellum's scope. If an operator on the same host runs a packet-capture tool, Castellum's sniffer and their tool share the same NIC view. The container security policy must limit who can run additional processes alongside Castellum.

**D — Denial of Service**
A flood of ARP or mDNS traffic on the monitored segment could cause `PcapSniffer` to buffer large frame queues. The libpcap BPF filter should be as specific as possible (e.g. `arp or mdns`) to discard irrelevant traffic before it reaches user space. Without a tight BPF filter, a broadcast storm could exhaust JVM heap.

**E — Elevation of Privilege**
CAP_NET_RAW itself is a capability elevation relative to a normal process. The Docker security policy (`--cap-drop=ALL --cap-add=NET_RAW`) scopes this capability to packet capture only. If the container were started with `--privileged` instead, all capabilities would be granted — the `docker run` and Compose configuration must specify `cap_add: [NET_RAW]` explicitly, not `privileged: true`. See [documentation/runtime-flags.md](runtime-flags.md).

---

### Module 3 — Threat-Intel Ingest

Package: `cve/` — `NvdClient`, `NvdSyncService`, `CveMatcher`; `risk/EpssClient`, `risk/KevClient`
Trust boundary: Castellum → NVD/EPSS/CISA (egress HTTPS via reverse-proxy TLS)

**S — Spoofing**
NVD, EPSS, and CISA are accessed via HTTPS. DNS hijacking or a BGP prefix hijack could redirect requests to a malicious server. Java's default TLS verification checks the certificate chain against JDK trust anchors; an expired or self-signed certificate on the upstream would cause a connection failure rather than silent data acceptance. Mitigation: do not disable TLS verification; monitor NVD API key usage via NIST dashboard.

**T — Tampering**
An attacker who compromises the NVD API or the CISA KEV JSON endpoint could inject false CVE records (inflated CVSS scores, fabricated KEV entries) that would skew composite risk scores. NVD currently does not sign individual CVE records. The only defence is monitoring risk-score distributions for anomalous spikes after a sync. The `NvdSyncService` bulk-inserts all received records without signature validation — this is a known limitation.

**R — Repudiation**
N/A — this module is an ingest-only consumer. The NVD feed does not have a repudiation property relevant to Castellum.

**I — Information Disclosure**
The `CASTELLUM_NVD_API_KEY` is stored as an environment variable and referenced via `@Value("${castellum.nvd.api-key:}")` in `NvdClient`. If the JVM process dumps its environment (e.g. via a JMX exploit or `/proc/self/environ` read), the API key would be disclosed. The key is not a high-value secret (NVD keys are free and rate-limit-only), but it should still be treated as a credential. Mitigation: restrict access to the Castellum host's process environment.

**D — Denial of Service**
NVD rate-limits anonymous clients to 5 requests / 30 seconds. With an API key, the limit is 50 / 30 seconds. If `CASTELLUM_NVD_API_KEY` is absent during a bulk sync, the full initial pull takes 3–4 hours and ties up the sync executor thread. No user-visible functionality is blocked during this time, but it delays CVE enrichment. See [documentation/operations.md](operations.md) for key registration.

**E — Elevation of Privilege**
N/A — ingest-only module with no user-facing privilege path.

---

### Module 4 — Risk Scorer

Package: `risk/CompositeScorer`, `risk/RiskFeedScheduler`, `risk/RiskInputs`
Trust boundary: pure function (no I/O); inputs come from the CVE mirror and device table

**S — Spoofing**
N/A — pure function. No external identity is involved.

**T — Tampering**
`CompositeScorer.score(RiskInputs)` is a deterministic pure function; its formula constants are `private static final` in the class. An attacker cannot tamper with the scoring formula at runtime without replacing the JAR. The risk inputs (CVSS score, EPSS probability, KEV membership, device criticality) are read from the database and can be tampered with if the database is compromised. Tampered CVSS scores from a poisoned NVD feed (see Module 3 Tampering) flow through unchanged. The golden-file tests in `src/test/resources/risk/golden/` pin known inputs to expected outputs and would detect formula drift if the constants were changed in code.

**R — Repudiation**
N/A — pure function. Risk score queries are recorded in the audit log at the REST layer (Module 10).

**I — Information Disclosure**
`GET /api/risk/score` returns composite risk scores to `VIEWER`+ users. A viewer can enumerate risk scores for all device/CVE pairs, indirectly revealing which devices the operator considers critical (via the `critMult` factor). This is intentional — VIEWER is an authenticated, authorised role.

**D — Denial of Service**
N/A — pure function. The scheduler (`RiskFeedScheduler`) runs EPSS/KEV refresh daily and is not user-triggered.

**E — Elevation of Privilege**
N/A — pure function with no privilege decision.

---

### Module 5 — Attack Graph

Package: `graph/` — `GraphBuilder`, `ShortestPathFinder`, `AttackTechniqueMapper`, `EdgeWeights`
Trust boundary: in-process (JGraphT); reachability results exposed via REST

**S — Spoofing**
The `GET /api/graph/shortest-path` endpoint requires `VIEWER`+ authentication. Spoofing the identity of a VIEWER requires stealing or forging a JWT (see Module 8).

**T — Tampering**
The attack graph is built from the live device and network-service inventory. If an attacker can manipulate device records (e.g. inject a device with an exploitable CVE on the same subnet as a target), they can influence the graph output to show — or hide — attack paths. Input to `GraphBuilder` must be trusted only as much as the inventory is trusted.

**R — Repudiation**
Every `GET /api/graph/shortest-path` call is recorded in the audit log with `{from, to, totalHops, cumulativeRisk}`. An operator cannot deny having queried reachability between two devices.

**I — Information Disclosure**
The shortest-path response reveals the complete hop sequence between two devices, including the specific CVE on each `EXPLOITABLE_VULN` hop. This is intentional for an authenticated VIEWER — the defender needs this data. However, the endpoint is a "reachability oracle": any authenticated user can determine whether device A can reach device B and via what path. In a high-security context, this oracle might need to be restricted to ADMIN only.

**D — Denial of Service**
The graph is rebuilt on every query (v1 design decision: no caching). A large inventory (e.g. 10,000 devices) with dense edge sets could cause a query to consume significant CPU and memory. The `GRAPH_SUBNET_CAP` (default 64) and `GRAPH_VULNS_PER_PAIR_CAP` (default 5) caps bound memory usage. Without these caps, a `/24` with all devices in scope could generate 64×63/2 = 2016 SAME_SUBNET edges. At 10,000 devices, an uncapped build would attempt ~50 million edges. Operators should tune these caps for their environment.

**E — Elevation of Privilege**
N/A — the graph is a read path. No privilege escalation vector exists within the graph module itself.

---

### Module 6 — OT/ICS Probes

Package: `ot/` — `ModbusProbe`, `Dnp3Probe`, `S7Probe`, `BacnetProbe`, `HostValidator`
Trust boundary: Castellum → OT network segment (TCP; read-only function-code whitelist)

**S — Spoofing**
The probe target is validated by `HostValidator` to be a dotted-quad IPv4 address; hostnames are rejected to prevent DNS-based SSRF. A rogue DNS response cannot redirect a probe because DNS is bypassed entirely. An attacker who controls an OT device's IP address (ARP spoofing) could serve crafted Modbus responses to misidentify the device vendor/product. Mitigation: validate fingerprint results against multiple protocol responses where possible.

**T — Tampering**
Each OT probe protocol implementation is restricted to read-only function codes. For Modbus: only Function Code 43 (Device Identification) and FC 04 (Read Input Registers for version data). Any attempt to include write function codes (FC 05/06/15/16) must be rejected at the level of the protocol builder. The read-only contract is documented in [documentation/ot-probes.md](ot-probes.md) and is a safety-critical property — violating it could cause unintended OT state changes. Code review of the `ot/` package must verify that no write function codes are ever constructed.

**R — Repudiation**
OT probe requests are submitted via `POST /api/ot-probe` which requires `ADMIN` role and triggers an audit log entry. An operator cannot deny having probed a specific OT host.

**I — Information Disclosure**
Probe responses include vendor, product, and firmware version strings for OT devices. This data is sensitive in an OT context — it reveals exactly what hardware is deployed and what version it is running, enabling targeted exploit selection. Probe results are accessible to `VIEWER`+ users. In high-security OT deployments, probe data should potentially be restricted to ADMIN access only.

**D — Denial of Service**
A tight TCP connect timeout (`OT_PROBE_CONNECT_TIMEOUT_MS` default 3000 ms) and total timeout (`OT_PROBE_TOTAL_TIMEOUT_MS` default 10000 ms) bound the duration of each probe. The `max-concurrent` cap (default 8) prevents probe storms. An ADMIN who submits many simultaneous probe requests could saturate the OT network segment. Operators in safety-critical environments should consider further tightening `max-concurrent` to 1–2.

**E — Elevation of Privilege**
N/A — the probe module sends read-only TCP packets and writes fingerprint results to the inventory. There is no privilege escalation vector within this module.

---

### Module 7 — Threat-Intel Export

Package: `threatintel/` — `BundleAssembler`, `stix/`, `taxii/`, `misp/`
Trust boundary: Castellum → TAXII/MISP partners (egress HTTPS + authentication)

**S — Spoofing**
TAXII pushes use HTTP Basic authentication (`TAXII_USERNAME` / `TAXII_PASSWORD`). MISP pushes use an API key header (`MISP_API_KEY`). These credentials are set as environment variables. If the TAXII or MISP endpoint is a malicious impersonator (e.g. via DNS hijacking), Castellum would push the inventory bundle to the attacker. Mitigation: HTTPS with valid certificate chain verification; do not set `TAXII_BASE_URL` or `MISP_BASE_URL` to plain HTTP in production.

**T — Tampering**
The STIX 2.1 bundle is assembled from the local inventory by `BundleAssembler`. An attacker who can modify device records before export could inject false indicators into the STIX bundle. The bundle is pushed to TAXII/MISP without a digital signature — the receiving platform cannot distinguish a Castellum-generated bundle from a bundle that was tampered with in transit (although HTTPS provides transport integrity). A future enhancement could sign STIX bundles with a private key.

**R — Repudiation**
Every export action (`export`, `push/taxii`, `push/misp`) requires `ADMIN` role and is recorded in the `threat_intel_push` audit table (see [documentation/stix-taxii-misp.md](stix-taxii-misp.md)). An operator cannot deny having pushed a bundle.

**I — Information Disclosure**
The STIX bundle contains the full device inventory with vulnerability data. Pushing to an external MISP or TAXII server transfers this data outside the Castellum deployment boundary. Operators must treat the TAXII/MISP destination as a trusted partner. Misconfigured `MISP_BASE_URL` pointing to an unintended server would exfiltrate the inventory.

**D — Denial of Service**
TAXII and MISP pushes are synchronous HTTP calls. A slow or unresponsive upstream would block the push thread. The `RestTemplate` / `WebClient` used for pushes should have a read timeout configured. Without a timeout, a stalled TAXII server could tie up the export endpoint indefinitely.

**E — Elevation of Privilege**
Export endpoints require `ADMIN` role. A VIEWER cannot trigger an export. Privilege escalation would require JWT forgery (Module 8).

---

### Module 8 — Auth / RBAC

Package: `security/` — `JwtService`, `JwtAuthenticationFilter`, `BootstrapAdminInitializer`, `Role`, `User`; `config/SecurityConfig`
Trust boundary: external requests → API; highest-impact module for spoofing and elevation

**S — Spoofing**
JWT tokens are signed with HMAC-SHA256 using `CASTELLUM_SECURITY_JWT_SECRET`. An attacker who obtains the secret can forge tokens for any user and role. The secret must be ≥ 32 bytes (enforced at startup — the application rejects the default placeholder unless the `test` Spring profile is active). The 1-hour TTL limits the window of a stolen token. Bootstrap admin credentials must not be committed to source control; see [documentation/auth.md](auth.md) §Bootstrap-admin.

**T — Tampering**
The `JwtService` verifies the HMAC signature on every request. A tampered token (e.g. role claims changed from `VIEWER` to `ADMIN`) will fail signature verification and be rejected with 401. The algorithm header (`alg`) is fixed to HS256 in the service; `alg: none` JWT attacks are not possible because the verifier enforces algorithm identity.

**R — Repudiation**
Login events and token issuances are not individually audited in v1. An operator who claims a login occurred at a specific time cannot produce a login-event audit record — only subsequent API calls produce audit entries. Enhancement: log `LOGIN_SUCCESS` and `LOGIN_FAILURE` events to the audit log.

**I — Information Disclosure**
The `CASTELLUM_ADMIN_PASSWORD_HASH` is a BCrypt-12 hash; disclosure of the hash does not directly reveal the plaintext password (BCrypt-12 requires ~8s per guess on modern hardware). The `CASTELLUM_SECURITY_JWT_SECRET` is more sensitive — anyone who obtains it can forge tokens. Both are stored in environment variables, not in application.properties files or source code. Secrets must not appear in container image layers.

**D — Denial of Service**
The `/api/auth/login` endpoint is not rate-limited in v1 (AC-7 non-claim; see [documentation/compliance.md](compliance.md)). An attacker can brute-force the admin password without lockout. Mitigation: reverse-proxy rate limiting (e.g. nginx `limit_req_zone`). BCrypt-12's 8 s/guess cost limits brute-force speed even without lockout.

**E — Elevation of Privilege**
Role assignment is performed by `BootstrapAdminInitializer` at startup (ADMIN) and would be performed by a future user-management endpoint (not yet implemented). In v1, only ADMIN and VIEWER roles exist. An attacker who can submit a `POST /api/auth/login` with valid admin credentials obtains an ADMIN token; no further escalation vector exists within the application.

---

### Module 9 — Audit Log

Package: `audit/` — `AuditLog`, `AuditService`, `AuditLogRepository`
Trust boundary: append-only Postgres table; repudiation is the primary concern

**S — Spoofing**
N/A — the audit log is written by the application, not by external actors. The actor field in `AuditLog` is populated from the authenticated JWT subject; its integrity depends on JWT authentication (Module 8).

**T — Tampering**
`AuditLogRepository` intentionally exposes no `delete*` or `update*` methods — the repository interface is append-only by design. A direct database connection (bypassing the application) could delete or modify rows. Mitigation: the Postgres user the application connects as should have `INSERT` privilege only on `audit_log`; no `UPDATE` or `DELETE` on that table. This is an operator-responsibility item (not enforced by the application's DDL migration, which runs as the schema owner).

**R — Repudiation**
The audit log exists precisely to contain repudiation. Every mutating API call (scan submission, device create/update/delete, OT probe, threat-intel push) writes a row with actor, action, resource, payload snapshot, and timestamp. An actor who claims they did not perform an action can be refuted if the audit row exists.

**I — Information Disclosure**
Audit log records contain payload snapshots of mutating requests, which may include device IP addresses, vulnerability IDs, and export destination URLs. Audit log access should be restricted to ADMIN role. In v1, the audit log does not have its own REST endpoint — it is written to Postgres and accessible via DBA tooling. Future versions should expose a paginated read endpoint restricted to ADMIN.

**D — Denial of Service**
Inserting an audit record on every mutating operation adds one `INSERT` per request. At high request rates, this could become a write bottleneck on the `audit_log` table. For MVP scale (< 1000 requests/minute), this is not a concern. At higher throughput, an asynchronous audit write queue should be considered.

**E — Elevation of Privilege**
N/A — the audit log is a write-only path from the application's perspective. No privilege decision is made within the audit module.

---

### Module 10 — REST API Surface

Package: `web/` controllers + `web/dto/` + `web/GlobalExceptionHandler`
Trust boundary: external HTTP → service layer; secondary control plane for all other modules

**S — Spoofing**
All endpoints except `/api/auth/login` and `GET /actuator/health` require a valid JWT. The `JwtAuthenticationFilter` validates the token on every request. See Module 8 for JWT security properties.

**T — Tampering**
`GlobalExceptionHandler` ensures that unhandled exceptions return generic 500 responses — internal stack traces and class names are not exposed to clients. Path-variable and request-body inputs are validated via Bean Validation (`@Valid` + `@NotBlank`, etc.). Missing or malformed inputs return 400 without executing business logic. A scan CIDR value that bypasses `@Valid` and reaches `CidrValidator` directly is still rejected by the validator.

**R — Repudiation**
Audit log coverage for all mutating endpoints is described in Module 9. The audit service is wired into each controller that performs state changes.

**I — Information Disclosure**
The `GlobalExceptionHandler` must not leak internal exception messages containing database state, connection strings, or stack traces. Spring Boot's default error response includes an exception class name — this should be disabled in production via `server.error.include-exception=false` and `server.error.include-stacktrace=never` in `application.properties`.

**D — Denial of Service**
No rate limiting on the API layer in v1. All unauthenticated paths are limited to `/api/auth/login` and the health check — the blast radius of unauthenticated DoS is limited to these two endpoints. Authenticated DoS would require a stolen token. Reverse-proxy rate limiting is recommended for the login endpoint specifically.

**E — Elevation of Privilege**
The `@PreAuthorize` annotations on controller methods define the role gates. A misconfiguration that removes `hasRole('ADMIN')` from a mutating endpoint would allow any authenticated user to perform that action. Spring Security's method security is applied after JWT validation — both layers must be correct. Code review must verify that no `@PreAuthorize` annotation has been removed or weakened.

---

### Module 11 — Frontend

Package: `frontend/src/` — React 19 + Cytoscape.js + Vite
Trust boundary: browser → API; runs in the user's browser security context

**S — Spoofing**
The frontend stores the JWT in `localStorage` (or `sessionStorage`). XSS on any page would allow an attacker to steal the JWT and impersonate the user. Mitigation: Content Security Policy header on the API server restricts which scripts can execute; strict input sanitisation prevents injection into the topology graph (node labels from device hostnames or IPs must be escaped before rendering). See [documentation/frontend-topology-ui.md](frontend-topology-ui.md).

**T — Tampering**
The React frontend sends JSON to the REST API. Tampered requests (e.g. CSRF) require a logged-in browser session. CSRF mitigation: the API uses stateless JWT bearer tokens, not session cookies — CSRF attacks require the attacker to steal the Bearer token, which requires XSS. The double-submit CSRF pattern is not needed for pure JWT bearer APIs.

**R — Repudiation**
All actions the frontend can trigger (scan, probe, export) are audited at the API layer. The frontend does not independently audit actions.

**I — Information Disclosure**
The topology graph renders device IP addresses, hostnames, vendor names, and CVE IDs in the browser UI. A screenshot or browser cache export could disclose sensitive topology data. Browser-side data exposure is the operator's responsibility (secure workstation policy).

**D — Denial of Service**
Rendering a very large graph (thousands of nodes) in Cytoscape.js could lock up the browser tab. The `GRAPH_SUBNET_CAP` and `GRAPH_VULNS_PER_PAIR_CAP` caps (Module 5) bound the graph size at the API level. The frontend should also implement a maximum-node rendering limit with a warning.

**E — Elevation of Privilege**
The frontend UI conditionally renders ADMIN-only controls based on the roles claim in the JWT. A client-side bypass (editing localStorage to claim ADMIN role) does not grant actual elevated access — the JWT signature check at the API layer would fail. Frontend role checks are for UX only; all security decisions are enforced at the API.

---

## Top-5 Mitigations

These five controls address the highest-risk cross-cutting threats identified in the STRIDE analysis.

### 1. Argv-only nmap subprocess (`scan/NmapRunner`)

Nmap is executed via Java's `ProcessBuilder` with an explicit argument list (`String[]`), never via `Runtime.exec(String)` or shell interpolation. This eliminates OS command injection through the scan CIDR parameter. The invariant must be maintained in all future changes to `NmapRunner` — any refactor that introduces string concatenation before `ProcessBuilder` execution must be reviewed as a security-critical change.

Evidence: `NmapRunnerTest` includes injection-pattern test cases (`; id`, `$(whoami)`, backtick sequences).

### 2. SSRF guard (`scan/CidrValidator` + `ot/HostValidator`)

Two SSRF guards operate at different layers:

- `CidrValidator` validates the scan CIDR to a valid IP range and optionally rejects private RFC-1918 ranges.
- `HostValidator` validates OT probe targets to dotted-quad IPv4 addresses, rejecting hostnames (which could DNS-resolve to loopback, link-local, or other reserved ranges).

Without these guards, an attacker with ADMIN access could direct Castellum to probe internal infrastructure (database port, JMX endpoint, metadata service) using Castellum as a proxy.

### 3. JWT HS256 + BCrypt-12 (`security/JwtService`)

All API authentication uses HMAC-SHA256 signed JWT tokens. The signing secret is validated to be ≥ 32 bytes at startup; the application refuses to start with a weak or default secret outside the `test` profile. Admin passwords are stored as BCrypt strength-12 hashes (approximately 8 seconds per hash on modern hardware), making offline brute-force attacks impractical.

See [documentation/auth.md](auth.md) for the full JWT contract.

### 4. Append-only audit log (`audit/AuditLogRepository`)

The `AuditLogRepository` interface exposes only `save` and read methods — no `delete*` or `update*` methods. This design ensures that once an audit record is written, the application cannot modify or delete it through normal code paths. Database-level protection (restricting the application DB user's privileges on the `audit_log` table to `INSERT` and `SELECT` only) completes the control. See Module 9 Tampering note.

### 5. Distroless + CAP_NET_RAW only (`supply-chain/Dockerfile`)

The final container image uses `gcr.io/distroless/java21-debian12:nonroot` — no shell, no package manager, no debugging tools. The container is started with `--cap-drop=ALL --cap-add=NET_RAW` (or equivalently, `cap_add: [NET_RAW]` in Compose), granting only the capability required for passive packet capture. A shell-based container breakout is not possible when there is no shell. CAP_NET_RAW is the only elevated capability in the container.

See [documentation/supply-chain.md](supply-chain.md) for the full supply-chain posture.

---

## Out-of-Scope Adversaries

The following adversary classes are explicitly out of scope for Castellum v1. Claiming protection against them would be dishonest given the current implementation.

### Nation-state supply-chain compromise

Castellum does not implement SLSA level 3 provenance. The Maven build is not hermetically reproducible — builds depend on Maven Central at compile time. The cosign signing step is operator-driven (not automated in CI). An attacker who can inject a malicious dependency into Maven Central, the Eclipse Temurin JDK base image, or the distroless base image would compromise Castellum silently. The SBOM and Trivy gate provide visibility into known CVEs in dependencies but do not prevent novel supply-chain attacks. See [documentation/supply-chain.md](supply-chain.md) §Known limitations.

### Insider with root access

An operator who has `root` on the Castellum host or a DBA connection to the Postgres instance can bypass every application-level control. The audit log can be deleted, the JWT secret read from the environment, and all data exfiltrated. Castellum provides no protection against a malicious insider with OS-level access. This is a deployment context responsibility, not an application responsibility.

### Physical access

Physical access to the host hardware (memory cold-boot, hardware debugger, storage extraction) is out of scope. The distroless image does not provide cryptographic attestation of RAM contents. FDE on the Postgres storage volume is an operator responsibility.

### Side-channel attacks

Timing side-channels in BCrypt comparison, cryptographic key material in processor caches, and power/EM analysis of the JWT signing operation are not addressed. Standard JVM and OS mitigations (spectre/meltdown patches, ASLR, stack canaries) are assumed to be present in the deployment environment.

---

## Cross-References

| Document | Relevance |
|----------|-----------|
| [documentation/auth.md](auth.md) | JWT contract, RBAC matrix, bootstrap admin procedure, secret rotation |
| [documentation/supply-chain.md](supply-chain.md) | Distroless image, Trivy gate, SBOM, cosign signing, known limitations |
| [documentation/ot-probes.md](ot-probes.md) | Read-only OT probe contract, supported protocols, SSRF guard behaviour |
| [documentation/runtime-flags.md](runtime-flags.md) | CAP_NET_RAW docker flags, pcap4j JVM system properties |
| [documentation/stix-taxii-misp.md](stix-taxii-misp.md) | Threat-intel export audit trail, TAXII/MISP push configuration |
| [documentation/frontend-topology-ui.md](frontend-topology-ui.md) | Frontend architecture, XSS surface, topology graph rendering |
| [documentation/compliance.md](compliance.md) | NIST 800-53 control mapping informed by this threat model |
| [documentation/stanag-notes.md](stanag-notes.md) | NATO vocabulary alignment, NCIRC context |
