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
