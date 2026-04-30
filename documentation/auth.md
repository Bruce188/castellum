# Authentication

## RBAC matrix

| Method | Path | Required role |
|--------|------|---------------|
| POST | `/api/auth/login` | `permitAll` |
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
| GET | `/api/cve`, `/api/cve/{cveId}` | `VIEWER`+ |
| GET | `/api/risk/score`, `/api/risk/feeds/status`, `/api/risk/device/{id}` | `VIEWER`+ |
| POST | `/api/discovery/passive` | `ADMIN` |
| POST | `/api/ot-probe` | `ADMIN` |
| GET | `/api/graph/shortest-path` | `VIEWER`+ |
| POST | `/api/threat-intel/export`, `/api/threat-intel/push/taxii`, `/api/threat-intel/push/misp` | `ADMIN` |
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
```

### Multi-instance caveat

The in-memory limiter is **single-instance only**. Operators running multiple replicas must front Castellum with a shared rate-limiter (Redis-backed Bucket4j, an API gateway, or a load-balancer-level rule) and set `CASTELLUM_SECURITY_RATE_LIMIT_LOGIN_MAX_ATTEMPTS` to a high value locally. AC-7 NIST compliance is then satisfied at the gateway layer.

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
