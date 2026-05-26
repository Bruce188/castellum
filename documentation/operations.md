# Operations Runbook — Castellum

**Version:** 1.0 (Feature 10)
**Date:** 2026-04-29
**Audience:** Security operators and system administrators deploying and maintaining Castellum.

---

## Overview

This runbook covers the operational concerns that come up most frequently during initial deployment and day-to-day operation:

1. [NVD API-key registration](#1-nvd-api-key-registration) — mandatory for practical bulk CVE sync performance.
2. [Suricata wiring (direction B — ingest only)](#2-suricata-wiring-direction-b) — how to feed Suricata alerts into Castellum's audit log.
3. [TLS termination guidance](#3-tls-termination-guidance) — Castellum does not terminate TLS; reverse-proxy setup required.
4. [Bootstrap admin checklist](#4-bootstrap-admin-checklist) — pre-flight environment variables before first start.
5. [Runtime flags pointer](#5-runtime-flags-and-jvm-configuration) — pcap4j JVM flags and CAP_NET_RAW capability for passive discovery.
6. [Scan-policy lifecycle](#6-scan-policy-lifecycle) — cron-driven scans, auto-retry, rate-limit, and scope-cap controls (V14).
7. [Integration credential rotation](#7-integration-credential-rotation) — `CASTELLUM_INTEGRATION_KEY` rotation procedure for the V15 `integration_config` table.

For the security posture underpinning these decisions see [documentation/threat-model.md](threat-model.md). For the NIST 800-53 compliance mapping see [documentation/compliance.md](compliance.md).

---

## 1. NVD API-Key Registration

### Why this matters

Castellum's local NVD CVE mirror is built via the NVD 2.0 REST API. Without an API key, NIST rate-limits anonymous clients to **5 requests every 30 seconds**. The initial bulk pull of the full CVE corpus (~250k records) takes **3–4 hours** at this rate. With an API key, the limit rises to **50 requests every 30 seconds**, reducing the initial pull to approximately **30 minutes**.

The `cve/NvdClient` class reads the key via:

```java
@Value("${castellum.nvd.api-key:}")
private String nvdApiKey;
```

If the property is blank, the client operates in anonymous (keyless) mode — no error is thrown, the sync simply runs slower.

### Registration procedure

1. Open a browser and navigate to:
   ```
   https://nvd.nist.gov/developers/request-an-api-key
   ```

2. Provide your **email address** and **organisation name**. NIST does not charge for API keys; registration is free.

3. NIST will email the API key to the address provided, typically within a few minutes to a few hours on business days.

4. Set the key as an environment variable before starting Castellum:
   ```bash
   export CASTELLUM_NVD_API_KEY=<your-key-here>
   ```
   The Spring Boot property binding maps `CASTELLUM_NVD_API_KEY` to `castellum.nvd.api-key`.

5. Verify the key is active by checking the `nvd-bulk-sync.sh` output for a `200 OK` response without `X-RateLimit-Remaining: 0` warnings.

### Throughput reference

| Mode | Rate limit | Initial bulk pull (~250k CVEs) | Incremental (daily) |
|------|-----------|-------------------------------|---------------------|
| Anonymous (no key) | 5 req / 30 s | 3–4 hours | < 1 minute (up-to-date mirror) |
| Keyed | 50 req / 30 s | ~30 minutes | < 1 minute (up-to-date mirror) |

### Bulk sync commands

```bash
# Initial full pull (all CVEs from a given date):
./scripts/nvd-bulk-sync.sh --since 2002-01-01

# Pull with explicit API key (overrides env var for that run):
./scripts/nvd-bulk-sync.sh --since 2002-01-01 --api-key YOUR_KEY

# Date-windowed pull:
./scripts/nvd-bulk-sync.sh --since 2026-01-01 --until 2026-04-29

# Daily incremental (uses MAX(last_modified) from the cve table as cursor):
./scripts/nvd-bulk-sync.sh
```

`--since` and `--until` accept either a plain date (`YYYY-MM-DD`, expanded to `T00:00:00Z` by the shell script) or a full ISO-8601 instant (`YYYY-MM-DDTHH:MM:SSZ`). Passing an unrecognised value causes `NvdSyncRunner` to throw `IllegalArgumentException` with a message that echoes the offending argument; the JVM exits with code 1. Exit code 2 is reserved for unknown shell-level arguments (e.g. a misspelled flag name).

### NVD AWAITING_ANALYSIS lag

The CVE corpus (~250k records) is mirrored incrementally; not every record is enriched at pull time. Newly-published CVEs may carry `vulnStatus = "Awaiting Analysis"` for hours to days while NVD analysts add CVSS scores and CPE applicability data. The mirror faithfully reflects the NVD state at sync time. CVEs in this state appear in the `cve` table but their `cvss_v31_score` and `cve_cpe_match` rows may be empty. Running the daily incremental picks up enrichment when NVD publishes it. This is a property of the NVD data pipeline, not a Castellum defect.

---

## 2. Suricata Wiring (Direction B)

### Architecture overview

In v1, the Suricata integration is **direction B: ingest only**. Suricata writes security alerts to its `eve.json` event log. A Castellum file-tailer job reads new lines from that file, parses each JSON event, and inserts a corresponding row into the `audit_log` table tagged `source=suricata`.

```
Suricata sensor (network IDS)
        |
        | writes alerts as JSON events
        ▼
eve.json (Suricata's unified output file)
        |
        | file tail (inotify or polling)
        ▼
Castellum tailer job
  - reads new lines
  - parses JSON (alert.signature, alert.category, src_ip, dest_ip, timestamp)
  - maps to AuditLog(actor="suricata", action=<signature>, resource_type="NETWORK_EVENT")
        |
        ▼
audit_log table (source='suricata', append-only)
```

This design keeps Castellum in a read-only relationship with the IDS: Castellum does not control Suricata, does not generate rules for it, and does not modify its configuration.

### Why direction B, not direction A

Direction A — Castellum generating Suricata detection rules from the device inventory and CVE data — would require a CVE-to-Suricata-SID mapping table, a rule-template engine, and a mechanism to hot-reload Suricata rules without disrupting active sessions (`suricatasc -c reload-rules`). This is significantly more complex, carries risk of disrupting the IDS, and is out of scope for v1.

Direction A is a natural future enhancement once the device inventory and CVE data have been validated in a real deployment. It is not documented as implemented here.

### Configuration

The Suricata tailer expects the following environment variable:

```bash
export SURICATA_EVE_LOG_PATH=/var/log/suricata/eve.json
```

The tailer job is disabled if `SURICATA_EVE_LOG_PATH` is absent or blank. No error is thrown; Castellum operates normally without Suricata integration.

### Suricata eve.json format compatibility

Tested against Suricata 6.x and 7.x `eve.json` default output. The tailer reads the `alert`, `timestamp`, `src_ip`, `dest_ip`, `proto`, and `alert.signature` fields. Other event types (DNS, HTTP, TLS, flow) in the eve.json stream are currently ignored by the tailer — only `event_type: "alert"` lines are processed.

### Operator checklist for Suricata direction B

1. Ensure `eve.json` is accessible from the Castellum container (bind mount or shared volume).
2. Set `SURICATA_EVE_LOG_PATH` to the absolute path of `eve.json` inside the Castellum container.
3. Verify the Castellum process has read access to the file (file permissions, SELinux/AppArmor context if applicable).
4. After startup, check `audit_log` for rows with `source = 'suricata'` to confirm the tailer is running.
5. Monitor the `audit_log` row count for `source = 'suricata'` — a sudden stop indicates the Suricata sensor has stopped writing to `eve.json` or the file path has changed.

---

## 3. TLS Termination Guidance

### Why Castellum does not terminate TLS

Castellum is designed to be deployed behind a TLS-terminating reverse proxy. The application listens on plain HTTP (default port 8080) on the loopback or a private network interface. This is a deliberate architectural choice: TLS certificate management, renewal, and cipher-suite configuration are operator responsibilities that vary by deployment context (Let's Encrypt, internal PKI, mutual TLS, FIPS-compliant cipher suites, etc.).

From the compliance perspective, NIST 800-53 SC-8 (Transmission Confidentiality) is satisfied at the reverse-proxy boundary. See [documentation/compliance.md](compliance.md) §SC-8 for the explicit carve-out.

### Supported reverse proxies

Any TLS-terminating HTTP reverse proxy works. Three common options:

**nginx**

```nginx
server {
    listen 443 ssl;
    server_name castellum.example.com;

    ssl_certificate     /etc/ssl/certs/castellum.crt;
    ssl_certificate_key /etc/ssl/private/castellum.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
    }
}

# Redirect HTTP to HTTPS:
server {
    listen 80;
    server_name castellum.example.com;
    return 301 https://$host$request_uri;
}
```

**Caddy** (automatic HTTPS via Let's Encrypt)

```
castellum.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy handles certificate provisioning and renewal automatically when the domain resolves publicly. For internal deployments with an internal CA, use the `tls` directive with certificate paths.

**Traefik** (Docker Compose label-based)

```yaml
services:
  castellum:
    image: castellum:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.castellum.rule=Host(`castellum.example.com`)"
      - "traefik.http.routers.castellum.entrypoints=websecure"
      - "traefik.http.routers.castellum.tls.certresolver=letsencrypt"
      - "traefik.http.services.castellum.loadbalancer.server.port=8080"
```

### Rate limiting at the reverse proxy

Castellum implements in-application rate limiting on `/api/auth/login` (`LoginRateLimiter`,
10 fails per 60 s by default), `/api/auth/change-password`
(`PasswordChangeRateLimiter`, 3 attempts per 60 s by default), and `POST /api/scan`
(`ScanSubmissionRateLimiter`, 20 per 60-minute window). The reverse proxy is still
recommended for defence in depth — the in-process counters reset on process restart, so
a deliberate-crash brute-force loop could otherwise bypass the cap.

**nginx example** — additional protective layer in front of the in-app limiter for the
login endpoint at 10 requests per minute per IP:

```nginx
http {
    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;

    server {
        location /api/auth/login {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://127.0.0.1:8080;
        }
    }
}
```

See [documentation/auth.md](auth.md) for the full set of in-application limiter tunables.

---

## 4. Bootstrap Admin Checklist

Before starting Castellum for the first time, set the following environment variables. The application's `BootstrapAdminInitializer` performs an idempotent upsert of the admin account at startup; if the variables are absent or blank, it warns and skips — the database will have no users and all authenticated endpoints will be unreachable.

### Required environment variables

```bash
# 1. Admin username (any non-blank string):
export CASTELLUM_ADMIN_USERNAME=admin

# 2. BCrypt strength-12 hash of the admin password.
#    Generate with htpasswd (Apache utilities):
htpasswd -bnBC 12 "" "your-strong-password" | tr -d ':\n'
#    Or with OpenSSL + Java jshell:
#    jshell> new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(12).encode("password")

export CASTELLUM_ADMIN_PASSWORD_HASH='$2a$12$<hash-output-here>'

# 3. JWT signing secret — minimum 32 bytes (43 characters in base64).
#    Generate with:
openssl rand -base64 48

export CASTELLUM_SECURITY_JWT_SECRET="<base64-output-here>"
```

### Optional environment variables

```bash
# NVD API key (strongly recommended — see §1):
export CASTELLUM_NVD_API_KEY=<nvd-key>

# Suricata eve.json path (required for Suricata direction-B integration — see §2):
export SURICATA_EVE_LOG_PATH=/var/log/suricata/eve.json

# TAXII push target (see documentation/stix-taxii-misp.md):
export TAXII_BASE_URL=https://taxii.example.com
export TAXII_COLLECTION_ID=<collection-id>
export TAXII_USERNAME=<user>
export TAXII_PASSWORD=<pass>

# MISP push target:
export MISP_BASE_URL=https://misp.example.com
export MISP_API_KEY=<key>

# AES-256 base64 master key used by AesGcmCipher to encrypt integration_config
# credentials at rest (see §7). Required before the first PUT /api/integrations call.
export CASTELLUM_INTEGRATION_KEY=<base64-aes256-key>

# Risk feed refresh cron (default: 06:00 UTC daily):
export RISK_REFRESH_CRON="0 0 6 * * *"

# Attack graph caps:
export GRAPH_SUBNET_CAP=64
export GRAPH_VULNS_PER_PAIR_CAP=5

# OT probe timeouts (milliseconds):
export OT_PROBE_CONNECT_TIMEOUT_MS=3000
export OT_PROBE_READ_TIMEOUT_MS=5000
export OT_PROBE_TOTAL_TIMEOUT_MS=10000
export OT_PROBE_MAX_CONCURRENT=8
```

### Pre-flight checklist

Before starting the application:

- [ ] `CASTELLUM_ADMIN_USERNAME` is set to a non-default username (not "admin" in production if avoidable).
- [ ] `CASTELLUM_ADMIN_PASSWORD_HASH` contains a valid BCrypt-12 hash.
- [ ] `CASTELLUM_SECURITY_JWT_SECRET` is ≥ 32 bytes (the application rejects weak secrets at startup unless the `test` Spring profile is active).
- [ ] PostgreSQL 16 is running and the schema has been migrated via Flyway (runs automatically on startup).
- [ ] The reverse proxy is configured for TLS (see §3).
- [ ] `CASTELLUM_NVD_API_KEY` is set (recommended, not required).
- [ ] Container is started with `--cap-add=NET_RAW` if passive discovery is needed (see §5).
- [ ] The container image is verified with cosign before deployment (see [documentation/supply-chain.md](supply-chain.md)).

### Post-bootstrap verification

After first start:

```bash
# 1. Check the health endpoint (no auth required):
curl http://localhost:8080/actuator/health
# Expected: {"status":"UP"}

# 2. Obtain a JWT:
curl -X POST http://localhost:8080/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"your-password"}'
# Expected: {"token":"...","expiresAt":"...","roles":["ADMIN"]}

# 3. Test an authenticated call:
TOKEN=<token-from-above>
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/devices
# Expected: {"content":[],"totalElements":0,...} (empty inventory on first run)
```

See [documentation/auth.md](auth.md) for the full RBAC matrix and JWT contract details.

---

## 5. Runtime Flags and JVM Configuration

### CAP_NET_RAW for passive discovery

The passive discovery module (`discovery/PcapSniffer`, `ArpCacheReader`, `MdnsProbe`) requires raw packet capture capability. In a Docker deployment, this is granted via:

```bash
docker run --cap-drop=ALL --cap-add=NET_RAW castellum:latest
```

In Docker Compose:

```yaml
services:
  castellum:
    image: castellum:latest
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
```

**Do not use `--privileged`.** The `--privileged` flag grants all capabilities including `SYS_ADMIN`, `SYS_PTRACE`, and others that are not needed and that expand the container's attack surface significantly. Only `NET_RAW` is required.

If passive discovery is not used, `NET_RAW` is not required. The application starts and operates normally without it; passive discovery endpoints will fail with a permission error rather than silently.

### pcap4j JVM flags

pcap4j uses JNA (Java Native Access) to call libpcap. In some environments the following JVM system properties are required:

```bash
# Specify libpcap shared library path (if not in default library path):
-Djna.library.path=/usr/lib/x86_64-linux-gnu

# pcap4j network interface name (if not auto-detected):
-Dorg.pcap4j.core.pcapDev=eth0

# Promiscuous mode (default: true for PcapSniffer; set false to disable):
-Dorg.pcap4j.core.pcapPromisc=true
```

Pass these via the `JAVA_TOOL_OPTIONS` environment variable:

```bash
export JAVA_TOOL_OPTIONS="-Djna.library.path=/usr/lib/x86_64-linux-gnu -Dorg.pcap4j.core.pcapDev=eth0"
```

For the full list of pcap4j properties and known deployment issues (RHEL-based distros, Alpine musl libc, WSL2 packet capture limitations), see [documentation/runtime-flags.md](runtime-flags.md).

### Database connection configuration

```bash
# PostgreSQL connection (Spring Boot default property binding):
export SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/castellum
export SPRING_DATASOURCE_USERNAME=castellum
export SPRING_DATASOURCE_PASSWORD=<db-password>
```

Flyway runs schema migrations automatically on startup. On a clean database, migrations V1 through V9 (and beyond) run in sequence. On an existing database, only new migrations run.

### Logging level

```bash
# Reduce noise from NVD sync (verbose at INFO, quiet at WARN):
export LOGGING_LEVEL_IO_CASTELLUM_CVE=WARN

# Enable debug output for auth (useful during bootstrap):
export LOGGING_LEVEL_IO_CASTELLUM_SECURITY=DEBUG
```

---

## 6. Scan-Policy Lifecycle

### Schema (V14)

Migration `V14__scan_policy.sql` introduces two artefacts:

```sql
CREATE TABLE scan_policy (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    cron_expression TEXT NOT NULL,
    cidr TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_triggered_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_scan_policy_enabled ON scan_policy (enabled);

ALTER TABLE scan ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0;
```

`scan_policy` rows are managed through `POST /api/scan-policy` (create), `PUT
/api/scan-policy/{id}/disable`, `PUT /api/scan-policy/{id}/enable`, and `DELETE
/api/scan-policy/{id}`. All four endpoints are ADMIN-only. The `retry_count` column on
`scan` counts auto-retry attempts (see "Auto-retry" below).

### Cron-driven poller — `ScanPolicyScheduler`

`io.castellum.scan.ScanPolicyScheduler` wakes every 60 s (tunable via
`castellum.scan-policy.poll-interval-millis`) and iterates the enabled policies. For each
policy, it parses the cron expression with Spring's `CronExpression.parse(...)` and fires
the policy if its next-fire time relative to `last_triggered_at` has elapsed. Firing
inserts a fresh `scan` row in `PENDING` status, updates `scan_policy.last_triggered_at`,
emits `SCAN_POLICY_TRIGGER` to the audit log, and dispatches `ScanExecutionService#executeAsync`.

The scheduler runs as the system actor `scheduler` and bypasses
`ScanSubmissionRateLimiter` — the assumption is that the operator who created the policy
already accepted the cadence at policy-creation time. The scope guard runs regardless
(see "Scope cap" below) so a misconfigured policy fails closed at the next tick rather
than at create time.

### Submission rate limit — `ScanSubmissionRateLimiter`

Operator-initiated `POST /api/scan` calls go through `ScanSubmissionRateLimiter`, a
per-actor sliding-window limiter mirroring `LoginRateLimiter`. Defaults: 20 submissions
per 60-minute window per authenticated username, tunable via
`castellum.security.rate-limit.scan-window-seconds` (default `3600`) and
`castellum.security.rate-limit.scan-max-attempts` (default `20`). Overflow returns 429
with a `Retry-After` header. Keying is by username, not source IP, because the threat is
a single legitimate operator saturating `scanTaskExecutor`, not credential stuffing.

### Scope cap — `ScanSizeGuard`

`ScanSizeGuard.requireBoundedScope(cidr)` rejects any CIDR whose prefix is below `/22`
(1024 hosts). A `/16` against an unresponsive subnet at the F11 `--host-timeout 30s`
would otherwise need ~32 wall-clock minutes and blow through the 5-minute outer scan
timeout. The guard throws `ScanScopeTooLargeException` which `GlobalExceptionHandler`
maps to HTTP 400 with body `{"error": "scope_too_large", "message": "..."}`. The scope
guard runs at both `POST /api/scan` and at `ScanPolicyScheduler` fire time — there is no
way to schedule a `/16` policy that bypasses the cap at creation only.

### Auto-retry — `ScanRetryService`

Nmap-timeout failures (failure reason contains `"nmap timed out"`) auto-retry up to
`MAX_RETRIES = 2`. The retry uses a `60 × 3^(n-1)` second backoff — 60 s for attempt 1,
180 s for attempt 2. `ScanExecutionService` calls
`ScanRetryService#scheduleRetryIfApplicable` inside its failure branch; the row stays
`FAILED` with `retry_count` and `completed_at` set, and a `SCAN_RETRY_SCHEDULED` audit
row is written.

A separate `@Scheduled` poll (`pollDueRetries`, 30 s tick configurable via
`castellum.scan-retry.poll-interval-millis`) scans `FAILED` rows whose backoff has
elapsed, increments `retry_count`, clears `completed_at` / `failure_reason`, flips
status back to `PENDING`, emits `SCAN_RETRY`, and re-dispatches through
`ScanExecutionService`. Once `retry_count` hits `MAX_RETRIES` the row stays `FAILED`
permanently.

### Operator quick reference

```bash
# Create a daily 02:00 UTC scan policy for the demo lab subnet (ADMIN):
curl -X POST http://localhost:8080/api/scan-policy \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"lab-daily-02h","cronExpression":"0 0 2 * * *","cidr":"10.0.1.0/24","scanType":"PING_SWEEP"}'

# Disable temporarily:
curl -X PUT http://localhost:8080/api/scan-policy/42/disable -H "Authorization: Bearer $TOKEN"

# Hard-delete:
curl -X DELETE http://localhost:8080/api/scan-policy/42 -H "Authorization: Bearer $TOKEN"
```

The Settings page exposes the same surface through `ScanPolicyPanel`.

---

## 7. Integration Credential Rotation

### Schema (V15)

Migration `V15__integration_config.sql` introduces the `integration_config` table:

```sql
CREATE TABLE integration_config (
    id BIGSERIAL PRIMARY KEY,
    integration_type TEXT NOT NULL UNIQUE,
    config_json TEXT NOT NULL,
    encrypted_credentials BYTEA NOT NULL,
    last_push_at TIMESTAMP WITH TIME ZONE,
    last_push_status TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
```

One row per `integration_type` (`TAXII`, `MISP`, `STIX`). Non-secret config (URL,
collection id, etc.) lives in `config_json` as JSON text. Secrets (TAXII password, MISP
API key) live in `encrypted_credentials` as AES-256-GCM ciphertext: 12-byte IV prefix,
ciphertext, 16-byte auth tag. Encryption is handled by `io.castellum.security.AesGcmCipher`.

### Master-key configuration

```bash
# Generate a fresh AES-256 base64 key (32 raw bytes → 44 base64 chars):
openssl rand -base64 32

# Or via the in-JVM helper:
# jshell> System.out.println(io.castellum.security.AesGcmCipher.generateBase64Key())

# Export before starting Castellum:
export CASTELLUM_INTEGRATION_KEY="<base64-key-here>"
```

`AesGcmCipher` reads the key from `castellum.integration.key` (env-mapped to
`CASTELLUM_INTEGRATION_KEY`). Startup fails fast if the key is present but does not
decode to exactly 32 bytes; an absent key is logged at WARN and tolerated, but the
first call to `encrypt` / `decrypt` will throw — bring the key online before the
first integration save or push.

### Rotation procedure ("truncate + re-enter")

V15 does not ship a key-rotation helper, so rotation is a controlled wipe-and-replace.
The procedure is:

1. **Notify operators.** While the old key is still active, capture the current TAXII
   / MISP / STIX configuration values (URLs, collection ids, credentials) — these will
   need to be re-entered by hand after the rotation. The `config_json` column is
   plaintext and survives the rotation; only `encrypted_credentials` is wiped.

2. **Stop Castellum.** A live process cannot tolerate a key swap mid-flight; the
   next `decrypt` call after the swap would throw `IllegalStateException("AES-GCM
   decryption / tag-verify failed")` because the GCM tag was computed under the old
   key.

3. **Truncate the table.** From psql or your DBA tool:

   ```sql
   TRUNCATE TABLE integration_config;
   ```

   No row in this table can be salvaged across a key rotation — the IV is per-row
   but the master key is shared, so every row's ciphertext is unreadable after the
   swap.

4. **Replace the env var.** Update the shell / systemd unit / Docker Compose file
   to export the new `CASTELLUM_INTEGRATION_KEY`. Confirm it decodes to 32 bytes
   before starting:

   ```bash
   echo "$CASTELLUM_INTEGRATION_KEY" | base64 -d | wc -c   # must print 32
   ```

5. **Restart Castellum.** Verify startup with `curl /actuator/health` — a wrong-length
   key surfaces as a startup-time `IllegalStateException` from `AesGcmCipher#verifyKey`.

6. **Re-enter integration credentials.** As an ADMIN, repost each TAXII / MISP / STIX
   configuration via `PUT /api/integrations/{type}` or via the Settings page
   (`TaxiiConfigPanel`, `MispConfigPanel`, `StixExportPanel`). Each save emits an
   `INTEGRATION_CONFIG_SAVE` audit row so the rotation is traceable.

7. **Smoke-test push.** Trigger a `POST /api/integrations/{type}/push` for at least
   one configured type; the controller decrypts `encrypted_credentials` before
   invoking the upstream client, so a successful push confirms the new ciphertext
   round-trips correctly.

### Why no online rotation

Online rotation would require re-encrypting every row under the new key inside a single
transaction, which the cipher class does not currently support — there is no `rewrap`
helper and no second key slot. The "truncate + re-enter" pattern keeps the operational
footprint minimal at the cost of one round of manual re-entry per rotation. Operators
who need frequent rotation should script the truncate + restart + re-PUT sequence rather
than expand the in-application surface.

---

## Cross-References

| Document | Relevance |
|----------|-----------|
| [documentation/auth.md](auth.md) | Full RBAC matrix, JWT contract, BCrypt procedure, secret rotation |
| [documentation/supply-chain.md](supply-chain.md) | Dockerfile structure, distroless image, Trivy gate, cosign signing, SBOM artifacts |
| [documentation/runtime-flags.md](runtime-flags.md) | pcap4j JVM system properties, CAP_NET_RAW Docker flags, known platform issues |
| [documentation/ot-probes.md](ot-probes.md) | OT probe configuration (timeout env vars, max-concurrent), read-only contract |
| [documentation/compliance.md](compliance.md) | SC-8 TLS carve-out, AC-7 in-app rate-limiting evidence, SC-13/SC-28 at-rest crypto, Suricata SI-3/SI-4 conceptual wiring |
| [documentation/stix-taxii-misp.md](stix-taxii-misp.md) | TAXII / MISP / STIX endpoints powered by the `integration_config` rotation procedure documented in §7 |
| [documentation/threat-model.md](threat-model.md) | Security rationale for the operational choices documented here |
