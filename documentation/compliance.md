# Compliance Posture — NIST 800-53

**Version:** 1.0 (Feature 10)
**Date:** 2026-04-29
**Standard:** NIST SP 800-53 Rev. 5 — Security and Privacy Controls for Information Systems

---

## Posture Summary

Castellum is a solo-MVP defender tool. This document maps the NIST 800-53 controls that are **genuinely implemented** as of Feature 9. Only controls for which concrete implementation evidence exists are listed as implemented or partially implemented. Controls that are not yet implemented are called out explicitly — bare claims with no evidence are a red flag in any compliance review and are deliberately avoided here.

This mapping is not a formal Assessment and Authorisation (A&A) package. It is an honest engineering statement of what exists. A formal ATO (Authority to Operate) would require a Security Assessment Report, a System Security Plan, and independent testing. None of those exist for this MVP.

The control families covered are: AC (Access Control), AU (Audit and Accountability), CM (Configuration Management), IA (Identification and Authentication), RA (Risk Assessment), SC (System and Communications Protection), SI (System and Information Integrity), and SR (Supply Chain Risk Management).

Out-of-scope families with explicit justification are listed at the end of this document.

---

## NIST 800-53 Control Mapping

| Control | Family | Castellum Implementation | Evidence |
|---------|--------|--------------------------|----------|
| AC-2 | Access Control — Account Management | `BootstrapAdminInitializer` performs an idempotent upsert of the admin account at startup. `Role` enum constrains valid roles to `ADMIN` and `VIEWER`. No orphaned accounts can be created via the current API (no user-management endpoint in v1). | [documentation/auth.md](auth.md) §Bootstrap-admin |
| AC-3 | Access Control — Access Enforcement | `SecurityConfig` enforces role-based access on every endpoint via `hasRole('ADMIN')` / `hasAnyRole('VIEWER','ADMIN')` expressions. Mutating endpoints (POST, PUT, DELETE) require `ADMIN`; read endpoints require `VIEWER`+. | [documentation/auth.md](auth.md) §RBAC matrix |
| AC-7 | Access Control — Unsuccessful Logon Attempts | **Not implemented.** The `/api/auth/login` endpoint is not rate-limited or locked out in v1. BCrypt-12 cost (approximately 8 s/guess) slows brute-force but does not stop it. Operator-level rate limiting at the reverse proxy (e.g. nginx `limit_req_zone`) is required to satisfy this control. | [documentation/operations.md](operations.md) §TLS and reverse-proxy guidance; see also [documentation/threat-model.md](threat-model.md) Module 8 DoS row |
| AU-2 | Audit and Accountability — Event Logging | `AuditService.recordEvent` is wired into all mutating controllers: scan submission, device create/update/delete, OT probe, threat-intel push. The schema captures: actor (username), action (string), resource type + ID, payload snapshot (JSONB), and timestamp. | `backend/src/main/java/io/castellum/audit/AuditService.java` |
| AU-3 | Audit and Accountability — Content of Audit Records | Each `AuditLog` row captures: `id` (UUID), `actor`, `action`, `resource_type`, `resource_id`, `payload` (JSONB), `created_at` (timestamp with time zone). These fields satisfy the NIST minimum content requirement (event type, time, source, outcome, actor). | `backend/src/main/java/io/castellum/audit/AuditLog.java` |
| AU-9 | Audit and Accountability — Protection of Audit Information | `AuditLogRepository` extends Spring Data `Repository<AuditLog, UUID>` and exposes only `save` and read operations — no `delete*`, `deleteAll`, or `update*` methods are declared. The application cannot delete audit records via normal code paths. | `backend/src/main/java/io/castellum/audit/AuditLogRepository.java` |
| CM-7 | Configuration Management — Least Functionality | OT protocol probes are strictly read-only: Modbus probes use Function Code 43 (Device Identification) and FC 04 (Read Input Registers) only. No write function codes (FC 05/06/15/16) are constructed. The Docker image drops all capabilities then adds only `NET_RAW`. No shell is present in the distroless final image. | [documentation/ot-probes.md](ot-probes.md) §Read-only contract; [documentation/supply-chain.md](supply-chain.md) §Dockerfile |
| IA-2 | Identification and Authentication — User Identification and Authentication | All API endpoints except `/api/auth/login` and `GET /actuator/health` require a valid `Authorization: Bearer <token>` JWT. `JwtAuthenticationFilter` validates the HMAC-SHA256 signature on every request. | [documentation/auth.md](auth.md) §JWT contract |
| IA-5 | Identification and Authentication — Authenticator Management | Admin passwords are stored as BCrypt strength-12 hashes. The plaintext password is never stored. `CASTELLUM_ADMIN_PASSWORD_HASH` is set as an environment variable, not embedded in source code or image layers. JWT secret rotation requires restarting the application with a new `CASTELLUM_SECURITY_JWT_SECRET` value, which invalidates all outstanding tokens. | [documentation/auth.md](auth.md) §Bootstrap-admin, §Secret rotation |
| RA-5 | Risk Assessment — Vulnerability Monitoring and Scanning | Castellum maintains a local NVD CVE mirror (~250k records) refreshed via the NVD 2.0 REST API. `CveMatcher` performs CPE-to-CVE range-aware matching against the mirror. `CompositeScorer` enriches with EPSS exploitation probability and CISA KEV membership. | `backend/src/main/java/io/castellum/cve/CveMatcher.java`; `backend/src/main/java/io/castellum/risk/CompositeScorer.java` |
| SC-8 | System and Communications Protection — Transmission Confidentiality and Integrity | **Operator responsibility.** Castellum does not terminate TLS. The application listens on plain HTTP (default port 8080 on loopback). The operator must deploy a TLS-terminating reverse proxy (nginx, Caddy, or Traefik) in front of Castellum. SC-8 is satisfied at the proxy boundary; Castellum itself satisfies it for egress calls to NVD, EPSS, CISA, and MISP/TAXII (HTTPS). | [documentation/operations.md](operations.md) §TLS termination guidance |
| SC-13 | System and Communications Protection — Cryptographic Protection | JWT tokens use HMAC-SHA256 (`HS256`). Password storage uses BCrypt with cost factor 12. No weak algorithms (MD5, SHA-1, DES) are used in the authentication path. | `backend/src/main/java/io/castellum/security/JwtService.java`; [documentation/auth.md](auth.md) §JWT contract |
| SI-3 | System and Information Integrity — Malicious Code Protection | **Conceptual wiring; not fully implemented.** Suricata can write `eve.json` events that a Castellum tail-consumer would ingest into the audit log with `source=suricata` tag. The ingest path design is documented but not deployed. See [documentation/operations.md](operations.md) §Suricata wiring for the v1 conceptual architecture. | [documentation/operations.md](operations.md) §Suricata wiring (direction B) |
| SI-4 | System and Information Integrity — System Monitoring | **Conceptual wiring; not fully implemented.** The Suricata eve.json ingest path (see SI-3) is the planned mechanism for feeding IDS alerts into Castellum's audit log. In v1, Castellum's own audit log is the primary monitoring artifact. | [documentation/operations.md](operations.md) §Suricata wiring (direction B) |
| SI-7 | System and Information Integrity — Software, Firmware, and Information Integrity | Docker images are signed with cosign by the operator. `build-and-scan.sh` gates the build on Trivy HIGH/CRITICAL CVE findings and extracts a CycloneDX SBOM (`sbom-image.cdx.json` and `target/bom.xml`/`target/bom.json`). | [documentation/supply-chain.md](supply-chain.md) §Build pipeline |
| SR-3 | Supply Chain Risk Management — Supply Chain Controls and Processes | Build uses official `maven:3.9-eclipse-temurin-21` builder image and `gcr.io/distroless/java21-debian12:nonroot` runtime image. Trivy scans for known CVEs in both. Maven Central dependencies are resolved at build time; the SBOM captures all JVM transitive dependencies. | [documentation/supply-chain.md](supply-chain.md) §Trivy gate, §SBOM |
| SR-4 | Supply Chain Risk Management — Provenance | Three SBOM artefacts are produced per build: `target/bom.xml` (CycloneDX XML, JVM deps), `target/bom.json` (CycloneDX JSON, JVM deps), `sbom-image.cdx.json` (CycloneDX JSON, container image). These provide a full bill of materials for both compile-time and runtime dependencies. | [documentation/supply-chain.md](supply-chain.md) §SBOM artifacts |

---

## Evidence-Link Policy

Every "implemented" claim in the table above links to a specific file or section that an auditor can read to verify the claim. This policy exists because:

1. Bare claims without evidence are unverifiable and meaningless in a compliance review.
2. If the linked file does not contain the stated evidence, the compliance claim is false — the mapping should be updated, not the evidence invented.
3. For code-level evidence (Java file references), the auditor should read the referenced source file directly. These references use package-relative paths (`io/castellum/...`) or short class names resolvable from the `backend/src/main/java/` root.

Any future update to this table that adds a new "implemented" row without a corresponding evidence link must be treated as a documentation defect.

### Distinguishing implementation states

The table uses three implementation states to be precise about what Castellum actually provides:

**Implemented** — the control is actively implemented in Castellum's code. Evidence exists in the linked file. An assessor can verify the claim by reading the referenced source or documentation.

**Deferred / Not implemented** — the control is known to be absent. The gap is acknowledged explicitly, not hidden. AC-7 (login rate-limiting) falls here; it is technically deferred to a future iteration, not accidentally omitted.

**Conceptual wiring** — the architectural path is designed and documented, but the code that runs it is not yet deployed. SI-3 and SI-4 (Suricata IDS integration) fall here. The design decision to use direction-B ingest (Suricata → eve.json → Castellum audit log) is made and documented, but the running file-tailer component does not yet ship with the application. Claiming "implemented" for these would be dishonest; claiming "not applicable" would be equally wrong.

**Operator responsibility** — the control is satisfied, but Castellum relies on the operator to configure an external component. SC-8 (TLS) is the primary example: the operator must deploy a TLS-terminating reverse proxy. Castellum cannot satisfy SC-8 alone; it requires a correctly configured deployment environment.

---

## Operator-Responsibility Carve-Outs

Two controls are partially satisfied only through operator action — Castellum does not implement them directly:

**SC-8 — Transmission Confidentiality.** Castellum does not terminate TLS. Deploying a TLS-terminating reverse proxy in front of Castellum is required for this control. See [documentation/operations.md](operations.md) §TLS termination guidance for the nginx/Caddy/Traefik setup pattern.

**AC-7 — Unsuccessful Logon Attempts.** No login rate-limiting or account lockout is implemented in Castellum v1. BCrypt-12's computational cost (approximately 8 seconds per attempt) limits brute-force speed but is not a substitute for rate limiting. Operators should configure rate limiting at the reverse proxy. This is an explicitly acknowledged gap, not an oversight.

---

## Explicit Non-Claims

The following NIST 800-53 control families are out of scope for Castellum v1. This is not an oversight — they are genuinely inapplicable or deferred for a solo MVP. A future System Security Plan must address them explicitly if Castellum is deployed in a regulated environment.

| Family | Reason for exclusion |
|--------|----------------------|
| CP-* — Contingency Planning | No backup/recovery procedures, no business continuity plan, no system recovery objectives defined. Solo MVP. |
| MP-* — Media Protection | No removable media policy. Castellum runs as a containerised service. Physical media handling is out of scope. |
| PE-* — Physical and Environmental Protection | Physical security of the deployment host is an operator/facility responsibility. Castellum provides no physical controls. |
| AT-* — Awareness and Training | No formal security awareness training programme. Solo MVP; no organisational training infrastructure. |
| IR-* — Incident Response | No formal incident response plan or team defined. Future operational deployments should establish IR procedures. |
| PL-* — Planning | No formal System Security Plan (SSP). This document is an engineering posture statement, not an SSP. |
| PS-* — Personnel Security | Personnel vetting and separation of duties policies are outside the scope of this application. |
| RA-3 — Risk Assessment (formal) | No formal risk assessment process. This threat model is an engineering artifact, not a formal RA-3 assessment. |
| SA-* — System and Services Acquisition | No formal acquisition process. Open-source MVP. |

---

## Cross-References

| Document | Relevance |
|----------|-----------|
| [documentation/threat-model.md](threat-model.md) | STRIDE analysis per module; source of truth for threat scenarios mapped to these controls |
| [documentation/auth.md](auth.md) | Implementation evidence for AC-2, AC-3, IA-2, IA-5, SC-13 |
| [documentation/supply-chain.md](supply-chain.md) | Implementation evidence for SI-7, SR-3, SR-4, CM-7 (distroless) |
| [documentation/ot-probes.md](ot-probes.md) | Implementation evidence for CM-7 (read-only OT) |
| [documentation/operations.md](operations.md) | Operator guidance for SC-8, AC-7, SI-3 (Suricata) |
