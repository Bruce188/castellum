# Operations Runbook — Castellum

**Version:** 1.0 (Feature 10)
**Date:** 2026-04-29
**Audience:** Security operators and system administrators deploying and maintaining Castellum.

---

## Overview

This runbook covers the five operational concerns that come up most frequently during initial deployment and day-to-day operation:

1. [NVD API-key registration](#1-nvd-api-key-registration) — mandatory for practical bulk CVE sync performance.
2. [Suricata wiring (direction B — ingest only)](#2-suricata-wiring-direction-b) — how to feed Suricata alerts into Castellum's audit log.
3. [TLS termination guidance](#3-tls-termination-guidance) — Castellum does not terminate TLS; reverse-proxy setup required.
4. [Bootstrap admin checklist](#4-bootstrap-admin-checklist) — pre-flight environment variables before first start.
5. [Runtime flags pointer](#5-runtime-flags-and-jvm-configuration) — pcap4j JVM flags and CAP_NET_RAW capability for passive discovery.

For the security posture underpinning these decisions see [documentation/threat-model.md](threat-model.md). For the NIST 800-53 compliance mapping (including SC-8 TLS and AC-7 rate-limiting gaps) see [documentation/compliance.md](compliance.md).

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

Since Castellum does not implement login rate-limiting in v1 (see NIST 800-53 AC-7 non-claim in [documentation/compliance.md](compliance.md)), the reverse proxy is the recommended location for this control:

**nginx example** — limit the login endpoint to 10 requests per minute per IP:

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

## Cross-References

| Document | Relevance |
|----------|-----------|
| [documentation/auth.md](auth.md) | Full RBAC matrix, JWT contract, BCrypt procedure, secret rotation |
| [documentation/supply-chain.md](supply-chain.md) | Dockerfile structure, distroless image, Trivy gate, cosign signing, SBOM artifacts |
| [documentation/runtime-flags.md](runtime-flags.md) | pcap4j JVM system properties, CAP_NET_RAW Docker flags, known platform issues |
| [documentation/ot-probes.md](ot-probes.md) | OT probe configuration (timeout env vars, max-concurrent), read-only contract |
| [documentation/compliance.md](compliance.md) | SC-8 TLS carve-out, AC-7 rate-limiting non-claim, Suricata SI-3/SI-4 conceptual wiring |
| [documentation/threat-model.md](threat-model.md) | Security rationale for the operational choices documented here |
