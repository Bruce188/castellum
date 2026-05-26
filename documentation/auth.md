# Authentication

## RBAC matrix

| Method | Path | Required role |
|--------|------|---------------|
| POST | `/api/auth/login` | `permitAll` |
| POST | `/api/auth/change-password` | authenticated (any role) |
| GET | `/api/devices`, `/api/devices/{id}` | `VIEWER`+ |
| POST | `/api/devices` | `ADMIN` |
| PUT | `/api/devices/{id}` | `ADMIN` |
| DELETE | `/api/devices/{id}` | `ADMIN` |
| GET | `/api/services`, `/api/services/{id}` | `VIEWER`+ |
| POST | `/api/services` | `ADMIN` |
| PUT | `/api/services/{id}` | `ADMIN` |
| DELETE | `/api/services/{id}` | `ADMIN` |
| POST | `/api/scan` | `ADMIN` |
| GET | `/api/scans`, `/api/scans/{id}` | `VIEWER`+ |
| GET | `/api/cve`, `/api/cve/{cveId}`, `/api/cve/fleet` | `VIEWER`+ |
| GET | `/api/risk/score`, `/api/risk/feeds/status`, `/api/risk/device/{id}`, `/api/risk/top` | `VIEWER`+ |
| POST | `/api/discovery/passive` | `ADMIN` |
| GET | `/api/discovery/interfaces` | `ADMIN` (degrades to 403→[] in client) |
| POST | `/api/ot-probe` | `ADMIN` |
| GET | `/api/graph/shortest-path` | `VIEWER`+ |
| POST | `/api/threat-intel/export`, `/api/threat-intel/push/taxii`, `/api/threat-intel/push/misp` | `ADMIN` |
| GET / POST | `/api/integrations/{taxii\|misp\|stix}` | `ADMIN` |
| GET / POST / PUT | `/api/users`, `/api/users/{id}` | `ADMIN` |
| GET / POST | `/api/scan/policy/*` | `ADMIN` |
| GET | `/api/audit` | `ADMIN` |
| GET | `/api/audit/csv` | `ADMIN` |
| GET | `/actuator/health` | `permitAll` |

`VIEWER`+ = `hasAnyRole('VIEWER','ADMIN')`. `ADMIN` = `hasRole('ADMIN')`.

## JWT contract

- **Algorithm**: `HMAC-SHA256` (`HS256`)
- **Transport**: `Authorization: Bearer <token>` request header
- **Claims**:
  - `sub` — username
  - `roles` — JSON array of role names (e.g. `["ADMIN"]`)
  - `iat` — issued-at (Unix epoch seconds)
  - `exp` — expiry (Unix epoch seconds)
  - `iss` — issuer, always `castellum`
- **TTL**: 3600 seconds (1 hour), configurable via `castellum.security.jwt.ttl-seconds`
- **Secret**: property `castellum.security.jwt.secret` / env `CASTELLUM_SECURITY_JWT_SECRET`; must be ≥32 bytes; the default placeholder is rejected unless the `test` Spring profile is active

## Bootstrap-admin procedure

The bootstrap-admin initializer runs at application startup and performs an idempotent upsert. If the env vars are absent or blank, it warns and skips.

```bash
# Generate a BCrypt strength-12 hash of the desired password:
htpasswd -bnBC 12 "" "your-password" | tr -d ':\n'
# Or via Java REPL (jshell):
# jshell> new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(12).encode("your-password")

export CASTELLUM_ADMIN_USERNAME=admin
export CASTELLUM_ADMIN_PASSWORD_HASH='$2a$12$...'
docker run -e CASTELLUM_ADMIN_USERNAME -e CASTELLUM_ADMIN_PASSWORD_HASH ... castellum:latest
```

The idempotent upsert means you can restart with new credentials; the existing user row is updated.

## Login flow

### Obtain a token

```bash
curl -X POST http://localhost:8080/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"your-password"}'
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "expiresAt": "2025-01-01T01:00:00Z",
  "roles": ["ADMIN"]
}
```

### Use the token

```bash
curl -H 'Authorization: Bearer <token>' http://localhost:8080/api/devices
```

### Error responses

| Scenario | HTTP status | Body |
|----------|-------------|------|
| Wrong password or unknown user | 401 | `{"error":"Unauthorized","status":401,"path":"/api/auth/login"}` |
| Valid token but insufficient role | 403 | `{"error":"forbidden","status":403,"path":"..."}` |
| Missing `Authorization` header | 401 | `{"error":"Unauthorized","status":401}` |
| Expired or tampered token | 401 | `{"error":"Unauthorized","status":401}` |
| Empty or malformed request body | 400 | `{"error":"...","status":400}` |

## Secret rotation

To rotate the JWT secret:

1. Generate a new secret: `openssl rand -base64 48`
2. Update `CASTELLUM_SECURITY_JWT_SECRET` in your deployment configuration.
3. Restart the application.

All in-flight tokens issued with the old secret will be immediately invalidated. Users will need to log in again to obtain a new token. There is no per-token blocklist (deferred item).

## Token Revocation

Castellum supports per-user token revocation via a `token_version` column (V10 migration, `INT NOT NULL DEFAULT 0`) on the `users` table. Every issued JWT carries a `tv` claim matching the user's current `token_version`.

`JwtAuthenticationFilter` performs a fresh DB read on every authenticated request and compares the token's `tv` claim against the stored value. A mismatch or disabled-user lookup causes the request to be rejected with HTTP 401 immediately — no waiting for token expiry (up to 1-hour drift without this feature).

### Admin disable endpoint

```
POST /api/users/{username}/disable   (ADMIN-only)
```

This endpoint atomically:
- Sets `enabled=false` on the target user.
- Increments `token_version` by 1.

Any outstanding JWT held by the disabled user will be rejected on the next request. Audit event: `USER_DISABLED` (resource=user).

The filter path emits `AUTH_TOKEN_REJECT` audit events with reason `token_version_mismatch` (version bump) or `user_disabled_or_missing` (disabled/not found).

## Viewer Bootstrap

Symmetric to the Bootstrap-admin procedure above. If `CASTELLUM_VIEWER_USERNAME` and `CASTELLUM_VIEWER_PASSWORD_HASH` are set at startup, `BootstrapAdminInitializer` mints or updates a VIEWER role user idempotently.

```bash
export CASTELLUM_VIEWER_USERNAME=viewer
export CASTELLUM_VIEWER_PASSWORD_HASH='$2a$12$...'
```

Hash recipe: `htpasswd -bnBC 12 "" "<password>" | tr -d ':\n'`

Hash drift (env hash differs from stored hash) triggers a `VIEWER_HASH_ROTATE` audit event and updates the stored hash.

## Login Rate-Limit

Castellum enforces a per-IP sliding-window rate limit on failed login attempts to mitigate BCrypt-12 amplification (NIST AC-7).

- **Default window**: 60 seconds, 10 max failed attempts.
- **11th request** in the window returns HTTP 429 with a `Retry-After: <seconds>` header.
- **Successful logins** do not consume the budget — only failed attempts count.
- **Audit event**: `LOGIN_RATE_LIMIT` (resource=auth) when a 429 fires.

### Configuration

```
CASTELLUM_SECURITY_RATE_LIMIT_LOGIN_WINDOW_SECONDS=60
CASTELLUM_SECURITY_RATE_LIMIT_LOGIN_MAX_ATTEMPTS=10
CASTELLUM_SECURITY_RATE_LIMIT_EVICTION_INTERVAL_MILLIS=60000
```

### Reverse-proxy client-address resolution

By default Castellum uses `request.getRemoteAddr()` (the direct TCP peer) as the key for rate-limiting.
When Castellum runs behind a trusted reverse proxy that sets `X-Forwarded-For`, switch to XFF mode:

```
# Strategy: remote-addr (default) | xff
CASTELLUM_SECURITY_RATE_LIMIT_CLIENT_ADDRESS_STRATEGY=xff

# Comma-separated CIDRs of trusted proxy IPs (required when strategy=xff)
CASTELLUM_SECURITY_RATE_LIMIT_TRUSTED_PROXIES=10.0.0.0/24,192.168.1.0/24
```

In `xff` mode the limiter keys on the **leftmost** IP in `X-Forwarded-For` when the direct caller is
within the trusted-proxy CIDR list. If the direct caller is **not** in the list, the limiter falls
back to `remoteAddr` — spoofed headers from untrusted networks are ignored.

Startup validation: if `client-address-strategy=xff` and `trusted-proxies` is empty, the application
refuses to start. Malformed CIDRs also cause a startup failure.

### Multi-instance caveat

The in-memory limiter is **single-instance only**. Operators running multiple replicas must front Castellum with a shared rate-limiter (Redis-backed Bucket4j, an API gateway, or a load-balancer-level rule) and set `CASTELLUM_SECURITY_RATE_LIMIT_LOGIN_MAX_ATTEMPTS` to a high value locally. AC-7 NIST compliance is then satisfied at the gateway layer.

## Change password

```
POST /api/auth/change-password
```

Any authenticated user can rotate their own password. The request
body carries the *current* password (re-authenticated against the
stored BCrypt hash) plus the proposed new password:

```json
{
  "currentPassword": "the-old-one",
  "newPassword": "the-new-one-min-12-chars"
}
```

Successful rotation:
- Re-hashes the new password with BCrypt strength-12.
- Increments `token_version` so every outstanding JWT for the user is
  rejected on the next request. The caller's own current token is
  invalidated too — the client must re-login after rotation.
- Clears `must_change_password` if it was set.
- Emits `PASSWORD_CHANGE` audit event.

Failure modes:
- 401 if `currentPassword` does not match the stored hash.
- 400 with `{"error":"weak_password","message":"..."}` if the new
  password fails the strength check (currently: ≥ 12 chars, must
  differ from current).
- 429 if the per-actor `PasswordChangeRateLimiter` sliding window
  (5 attempts / 60s by default) is exhausted.

## First-login forced rotation

The bootstrap-admin and viewer initializers set
`must_change_password = true` whenever they create OR update a user
from environment-variable hashes. `LoginResponse` exposes a
`mustChangePassword: boolean` field; when true the frontend mounts
`ForcePasswordRotation` in place of the routed app — no navigation
matches until the user successfully POSTs to
`/api/auth/change-password`.

## User management

ADMIN-only CRUD over `/api/users`:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/users` | List all users (id, username, role, enabled, lastLogin). |
| POST | `/api/users` | Create a user. Body: `{username, password, role}`. Password BCrypt-hashed at strength 12; `mustChangePassword=true` set by default so the operator's chosen password is rotated on first login. |
| PUT | `/api/users/{id}` | Update role / enabled state. |

`/api/users/{username}/disable` (POST, also ADMIN-only) remains the
fast-path for revoking access — it sets `enabled=false` and bumps
`token_version` atomically. Use this for "rage-revoke" scenarios; use
`PUT /api/users/{id}` with `{enabled: false}` for normal admin
deactivations.

## Security Headers

All API responses include the following security headers:

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'self'` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Frame-Options` | `DENY` |

**HSTS deployment caveat**: HSTS without TLS in front is a no-op — browsers ignore HSTS over plain HTTP. Operators running plain HTTP behind a reverse proxy must terminate TLS at the proxy. See `documentation/operations.md` for TLS termination guidance.

## CORS Origin Validator

At startup, Castellum validates `castellum.cors.allowed-origins` (env: `CORS_ALLOWED_ORIGINS`) and throws `IllegalStateException` if any origin is invalid — the application refuses to start with a broken CORS config.

Validation rules (in order):
1. Reject bare `*` wildcard — list specific origins.
2. Reject wildcard-subdomain patterns (e.g. `*.example.com`).
3. Reject `http://` schemes for non-localhost hosts. Only `http://localhost`, `http://localhost:NNNN`, and `http://127.0.0.1` are permitted under HTTP. Production origins must use `https://`.
4. Reject malformed URIs.

Dev default `http://localhost:5173` passes all rules. For production deployments, set a full `https://` origin.

## CVE Endpoint Response Shapes

Both CVE endpoints require at minimum the `VIEWER` role. They return distinct DTO types to control which fields are exposed.

### GET /api/cve?cpe=\<cpe-string\>

Returns an array of `CveSummaryDto` objects. Each object contains the structured CVE fields but **omits `rawJson`** to avoid bandwidth overhead on bulk list responses.

```json
[
  {
    "cveId": "CVE-2020-15778",
    "published": "2020-07-24T18:15:11Z",
    "lastModified": "2024-01-04T19:44:31Z",
    "vulnStatus": "Analyzed",
    "description": "scp in OpenSSH through 8.3p1 allows ...",
    "cvssV31Score": 7.8,
    "cvssV31Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "cvssV30Score": null,
    "cvssV30Vector": null,
    "cvssV2Score": 6.8,
    "cvssV2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
    "fetchedAt": "2026-05-01T06:01:23Z"
  }
]
```

Fields present on every object: `cveId`, `lastModified`. All remaining fields may be `null` when NVD has not yet published the corresponding data (e.g. CVEs in `Awaiting Analysis` status carry no CVSS scores).

### GET /api/cve/{cveId}

Returns a single `CveDetailDto` object. This is a superset of `CveSummaryDto`: all the same fields plus `rawJson`, which contains the full upstream NVD JSON payload.

```json
{
  "cveId": "CVE-2020-15778",
  "published": "2020-07-24T18:15:11Z",
  "lastModified": "2024-01-04T19:44:31Z",
  "vulnStatus": "Analyzed",
  "description": "scp in OpenSSH through 8.3p1 allows ...",
  "cvssV31Score": 7.8,
  "cvssV31Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
  "cvssV30Score": null,
  "cvssV30Vector": null,
  "cvssV2Score": 6.8,
  "cvssV2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
  "fetchedAt": "2026-05-01T06:01:23Z",
  "rawJson": "{\"id\":\"CVE-2020-15778\", ... }"
}
```

`rawJson` is the verbatim NVD JSON string stored during sync. It can be several kilobytes for heavily-annotated CVEs. The list endpoint intentionally omits it; use the detail endpoint when you need the full upstream payload.

Returns HTTP 404 if the CVE identifier is not present in the local mirror.

### Initial data sync

- **Endpoint**: `POST /api/admin/initial-sync` (ADMIN-only, `hasRole('ADMIN')`)
- **Response**: HTTP 202 with body `{ "status": "started" | "already-running", "startedAt": "<ISO8601>" }` — returns immediately; the actual ingest runs on the dedicated `initialSyncTaskExecutor` (1 thread, 0 queue).
- **Background job**: invokes `NvdSyncService.bulkPull(since, until)` then `EpssIngestionService.ingest()` then `KevIngestionService.ingest()` sequentially on the background thread; per-feed failure isolation ensures a transient NVD network error does not prevent EPSS+KEV from running.
- **Audit**: an `INITIAL_SYNC_TRIGGERED` audit row is emitted on every click — regardless of whether a sync is already in flight — so operators see every attempt.
- **Concurrency guard**: an in-memory `AtomicBoolean inFlight` prevents concurrent re-syncs; a second click while a sync is running returns 202 with `"already-running"` and the original `startedAt`.
- **Frontend signal**: the `EmptyCorpusBanner` component derives its visibility from `GET /api/risk/feeds/status` (polls every 10 s); the banner and its "Sync NVD + EPSS + KEV" button (admin only) disappear once all three `rowCount` fields are non-zero.
