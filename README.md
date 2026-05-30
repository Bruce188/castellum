# Castellum

Castellum is a NATO-track network topology and vulnerability mapper. It is an operational defender tool, not a generic scanner. Deployed inside a controlled network segment, it scans hosts, passively discovers devices, fingerprints OT/ICS equipment, enriches findings with NVD/EPSS/KEV data, computes composite risk scores, builds attack graphs, and exports threat intelligence to MISP or TAXII. License: Apache-2.0. Stack: Spring Boot 3.5.13 on Java 21 with virtual threads, PostgreSQL 16 + Flyway, React 19 + Vite + TypeScript frontend.

---

## Threat Model Summary

Full threat model: [documentation/threat-model.html](documentation/threat-model.html)

**Assets:** device inventory, CVE corpus (~250k records), risk scores, STIX export bundles, JWT signing key, admin password hash.

**Trust boundaries:**
- External → API (JWT authentication required; ADMIN/VIEWER roles)
- NIC → JVM via CAP_NET_RAW (passive packet capture; not `--privileged`)
- Castellum → OT network (read-only TCP probes; function-code whitelist)
- Castellum → NVD/EPSS/CISA/TAXII/MISP (egress HTTPS)
- JVM → nmap subprocess (argv array only; no shell interpolation)

**In-scope adversary:** network-adjacent attacker with HTTP access to the API; a web browser user on the frontend.

**Out-of-scope adversaries:** nation-state supply-chain compromise (no SLSA-3), insider with root access, physical hardware attacks, side-channel analysis.

**Top-5 mitigations:**
1. **Argv-only nmap** (`scan/NmapRunner`) — the nmap subprocess is launched via Java's `ProcessBuilder` with an explicit argument array, never via shell string interpolation. This eliminates OS command injection through the scan CIDR parameter. Test cases in `NmapRunnerTest` cover semicolon, backtick, and `$(...)` injection patterns.
2. **SSRF guard** (`scan/CidrValidator` + `ot/HostValidator`) — scan CIDRs are validated to a well-formed IP range. OT probe targets are validated to dotted-quad IPv4 addresses only; hostnames are rejected to prevent DNS-based redirection to loopback, metadata services, or internal infrastructure.
3. **JWT HS256 + BCrypt-12** (`security/JwtService`) — all API authentication uses HMAC-SHA256 signed tokens. The signing secret must be ≥ 32 bytes; the application refuses to start with a weak or default secret outside the `test` Spring profile. Admin passwords are stored as BCrypt strength-12 hashes (approximately 8 seconds per guess on modern hardware).
4. **Append-only audit log** (`audit/AuditLogRepository`) — the repository interface exposes only `save` and read operations; no `delete*` or `update*` methods are declared. All mutating API operations write an audit record. Database-level protection (application DB user with INSERT/SELECT only on `audit_log`) completes the control.
5. **Distroless + CAP_NET_RAW only** — the runtime image (`gcr.io/distroless/java21-debian12:nonroot`) has no shell, no package manager, and no debugging tools. The container is started with `--cap-drop=ALL --cap-add=NET_RAW` — only the single capability required for raw packet capture is granted.

---

## Compliance Posture

Full NIST 800-53 mapping: [documentation/compliance.md](documentation/compliance.md)

Mapped control families: AC (access control), AU (audit), CM (configuration), IA (authentication), RA (vulnerability scanning), SC (cryptography), SI (integrity), SR (supply chain).

**Explicit non-claims:**
- No SLSA-3 provenance (Maven build is not hermetically reproducible).
- No FIPS 140-3 (standard JVM crypto; BCrypt-12 is not FIPS-validated).
- No login rate-limiting in v1 — AC-7 is satisfied at the reverse proxy (operator responsibility).
- SC-8 (TLS) is satisfied at the reverse proxy, not within Castellum itself.
- CP-*, MP-*, PE-*, AT-* control families are out of scope for this solo MVP.

---

## NATO Context

Full alignment notes: [documentation/stanag-notes.md](documentation/stanag-notes.md)

> This section is not based on restricted-circulation directive text. Alignment with NATO standards is aspirational, based on public NATO communications only.

Castellum vocabulary (device, service, vulnerability, indicator) has been cross-walked against AAP-31 (NATO Glossary of CIS Terms). Most terms align closely; "device" vs AAP-31 "node" is the primary mismatch, flagged for future API evolution.

The MISP push capability (`POST /api/threat-intel/push/misp`) is the natural integration point with NCIRC (NATO Computer Incident Response Capability) threat-sharing fabrics. MISP is cited in public NCIRC documentation as a supported sharing mechanism. Castellum-generated STIX bundles can be pushed to an organisation's own MISP instance, which then participates in MISP federation or TAXII sharing with NATO partners.

---

## Demo

![Castellum scans a /24, discovers devices, fingerprints OT endpoints, scores risk, computes the shortest exploit path, exports a STIX 2.1 bundle, and pushes to MISP](documentation/img/demo.gif)

*The GIF above is a placeholder pending live recording. See [documentation/demo-script.md](documentation/demo-script.md) for the full 3-minute storyboard with cue-by-cue voice-over text, curl commands for each beat, and the ffmpeg pipeline for GIF capture.*

---

## Architecture

Application docs live under `documentation/`; the `docs/` directory is workflow scratch and is gitignored.

| Module | Package | Description |
|--------|---------|-------------|
| Active scanner | `scan/` | Hardened nmap runner (argv-only), CIDR validator, scan controller |
| Passive discovery | `discovery/` | pcap4j ARP sniffer, mDNS probe, LLDP/CDP decoder, ARP cache reader |
| Threat-intel ingest | `cve/`, `risk/` | Local NVD mirror (V2.0 API), EPSS daily fetch, CISA KEV ingestion |
| Risk scorer | `risk/CompositeScorer` | Pure function: CVSS × EPSS × KEV × criticality, range [0, 10] |
| Attack graph | `graph/` | JGraphT DijkstraShortestPath; ATT&CK technique annotation per edge — see [documentation/attack-graph.md](documentation/attack-graph.md) |
| OT/ICS probes | `ot/` | Read-only Modbus/TCP, DNP3, S7comm, BACnet/IP fingerprinters |
| Threat-intel export | `threatintel/` | STIX 2.1 bundle assembly, TAXII 2.1 push, MISP push |
| Auth/RBAC | `security/` | JWT HS256, BCrypt-12, ADMIN/VIEWER roles, bootstrap initializer |
| Audit log | `audit/` | Append-only Postgres table; all mutating operations recorded |
| REST API surface | `web/` | Spring MVC controllers, DTOs, global exception handler |
| Frontend | `frontend/src/` | React 19 + Cytoscape.js topology graph, Vite + TypeScript |

---

## Build and Run

### Prerequisites

- Java 21, Maven 3.9+
- PostgreSQL 16
- Node 20+ (frontend only)
- Docker (optional — for supply-chain pipeline)

### Quick start

```bash
# 1. Set required environment variables:
export CASTELLUM_ADMIN_USERNAME=admin
export CASTELLUM_ADMIN_PASSWORD_HASH="$(htpasswd -bnBC 12 '' 'your-password' | tr -d ':\n')"
export CASTELLUM_SECURITY_JWT_SECRET="$(openssl rand -base64 48)"
export SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/castellum
export SPRING_DATASOURCE_USERNAME=castellum
export SPRING_DATASOURCE_PASSWORD=<db-password>

# 2. Run backend (Flyway migrations run automatically):
cd backend && ./mvnw spring-boot:run

# 3. Run frontend dev server:
cd frontend && npm install && npm run dev

# 4. (Optional) Register an NVD API key and pull the CVE corpus:
export CASTELLUM_NVD_API_KEY=<your-key>
./scripts/nvd-bulk-sync.sh --since 2002-01-01
```

For the full operator runbook — including Suricata wiring, TLS termination with nginx/Caddy/Traefik, and bootstrap admin pre-flight checklist — see [documentation/operations.html](documentation/operations.html).

### Supply-chain pipeline

```bash
# Build, Trivy-scan, generate SBOM, emit cosign signing commands:
bash scripts/build-and-scan.sh
```

See [documentation/supply-chain.md](documentation/supply-chain.md) for the full supply-chain posture, including SBOM artifact locations and cosign signing procedure.

---

## API Reference

Full documentation for auth and RBAC: [documentation/auth.html](documentation/auth.html)
OT probe reference: [documentation/ot-probes.html](documentation/ot-probes.html)
STIX/TAXII/MISP reference: [documentation/threat-intel-integrations.html](documentation/threat-intel-integrations.html)
Runtime flags (pcap4j, CAP_NET_RAW): [documentation/runtime-flags.html](documentation/runtime-flags.html)
Supply-chain pipeline: [documentation/supply-chain.md](documentation/supply-chain.md)

All endpoints except `POST /api/auth/login` and `GET /actuator/health` require `Authorization: Bearer <token>`.

```bash
# Obtain a token:
curl -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"your-password"}'
```

| Group | Endpoints | Min role |
|-------|-----------|----------|
| Auth | `POST /api/auth/login` | public |
| CVE mirror | `GET /api/cve/{cveId}`, `GET /api/cve?cpe=...` | VIEWER |
| Scans | `POST /api/scan`, `GET /api/scans/{id}`, `GET /api/scans` | ADMIN (write), VIEWER (read) |
| Devices | `GET /api/devices`, `POST /api/devices`, `PUT /api/devices/{id}`, `DELETE /api/devices/{id}` | ADMIN (write), VIEWER (read) |
| Risk | `GET /api/risk/score`, `GET /api/risk/feeds/status`, `GET /api/risk/device/{id}` | VIEWER |
| Attack graph | `GET /api/graph/shortest-path?from=X&to=Y` | VIEWER |
| OT probes | `POST /api/ot-probe` | ADMIN |
| Passive discovery | `POST /api/discovery/passive` | ADMIN |
| Threat-intel export | `POST /api/threat-intel/export`, `POST /api/threat-intel/push/taxii`, `POST /api/threat-intel/push/misp` | ADMIN |
| Health | `GET /actuator/health` | public |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
