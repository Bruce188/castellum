# Threat Intelligence Export: STIX / TAXII / MISP

Castellum can export its vulnerability and device data as STIX 2.1 bundles and push them to a TAXII 2.1 collection or a MISP instance.

## STIX Bundle Structure

Each export produces one `bundle` containing:

| Object type | Source |
|---|---|
| `identity` (singleton) | Castellum system identity |
| `infrastructure` | Each discovered device (one per IP) |
| `vulnerability` | Each CVE associated with a network service |
| `relationship` (`affects`) | CVE → device pair |
| `indicator` + `relationship` (`targets`) | Emitted when KEV flag is set OR composite risk score ≥ 7.0 |

Object IDs are deterministic (UUIDv3/MD5 namespace) so repeated exports produce identical IDs for the same logical objects.

Timestamps use the STIX §3.4 format: `yyyy-MM-ddTHH:mm:ss.SSSZ`.

## REST Endpoints

All endpoints require `ROLE_ADMIN`.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/threat-intel/export` | Return bundle as `application/json` |
| `POST` | `/api/threat-intel/push/taxii?collection=<id>` | Push bundle to configured TAXII collection (optional override) |
| `POST` | `/api/threat-intel/push/misp` | Push bundle attributes to MISP event |

### Export Response

```
HTTP 200 application/json
{ ...stix bundle JSON... }
```

### TAXII Push Response

```json
{ "status": "pushed", "objects": 12, "bundle_id": "bundle--…", "status_code": 201 }
```

### MISP Push Response

```json
{ "status": "pushed", "bundle_id": "bundle--…", "misp_event_id": "42" }
```

### Error Responses

| HTTP | Cause |
|---|---|
| 502 Bad Gateway | Upstream TAXII or MISP server unreachable or returned unexpected response |
| 403 Forbidden | Caller does not have `ADMIN` role |

Every push attempt (including failures) is recorded in the `threat_intel_push` table and in the audit log.

## Configuration

Two configuration surfaces are supported. Pick exactly one — they are
mutually exclusive:

1. **`integration_config` table (V15 migration)** — the recommended
   path. Credentials are stored in Postgres encrypted at rest with
   AES-256-GCM. Managed through the admin UI (`TaxiiConfigPanel`,
   `MispConfigPanel`) or directly through `GET / POST /api/integrations/{taxii|misp|stix}`.
   The encryption key comes from `CASTELLUM_INTEGRATION_KEY` (see
   `runtime-flags.md § 7`); without that env var, the application
   refuses to load any encrypted row at boot.
2. **Environment variables (legacy)** — pre-V15 path, still honoured
   for ops parity. Credentials live in plaintext in the process env.
   Avoid for new deployments.

### Environment-variable form (legacy)

```env
# TAXII 2.1
TAXII_BASE_URL=https://taxii.example.com
TAXII_COLLECTION_ID=<default-collection-id>
TAXII_USERNAME=<user>
TAXII_PASSWORD=<pass>

# MISP
MISP_BASE_URL=https://misp.example.com
MISP_API_KEY=<api-key>
MISP_DISTRIBUTION=0       # 0=organisation only; 1=community; 2=connected; 3=all
MISP_THREAT_LEVEL_ID=2    # 1=high; 2=medium; 3=low; 4=undefined
```

### `/api/integrations` form (encrypted at rest)

```bash
# Configure TAXII
curl -X POST http://localhost:8080/api/integrations/taxii \
  -H "Authorization: Bearer <admin-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"baseUrl":"https://taxii.example.com","collectionId":"...","username":"...","password":"..."}'

# Configure MISP
curl -X POST http://localhost:8080/api/integrations/misp \
  -H "Authorization: Bearer <admin-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"baseUrl":"https://misp.example.com","apiKey":"...","distribution":0,"threatLevelId":2}'

# Read current (response masks the encrypted secret fields)
curl -H "Authorization: Bearer <admin-jwt>" http://localhost:8080/api/integrations/taxii
```

The `AesGcmCipher` uses a 12-byte random IV per record and a 128-bit
GCM authentication tag. Each row in `integration_config` stores the
IV concatenated with the ciphertext blob (column type `BYTEA` on
Postgres, `VARBINARY(4096)` on the H2 test profile). Decryption
failures surface as a 500 with `{"error":"integration_decrypt_failed"}`
so a wrong `CASTELLUM_INTEGRATION_KEY` after rotation fails loud
rather than silently misbehaving.

Corresponding `application.yml` keys:

```yaml
castellum:
  taxii:
    base-url: ${TAXII_BASE_URL:}
    collection-id: ${TAXII_COLLECTION_ID:}
    username: ${TAXII_USERNAME:}
    password: ${TAXII_PASSWORD:}
    backoff-base-millis: 6000
  misp:
    base-url: ${MISP_BASE_URL:}
    api-key: ${MISP_API_KEY:}
    distribution: ${MISP_DISTRIBUTION:0}
    threat-level-id: ${MISP_THREAT_LEVEL_ID:2}
    backoff-base-millis: 6000
```

## Retry Behaviour

Both `TaxiiClient` and `MispClient` retry up to 3 times on 5xx responses using exponential back-off. The back-off base is configurable (`backoff-base-millis`; default 6 s, matching `NvdClient`). Non-retryable errors (4xx, network reset) propagate immediately as `IOException`.

## Audit / Push Log

The `threat_intel_push` table captures every push attempt:

| Column | Description |
|---|---|
| `push_target` | `TAXII`, `MISP`, or `EXPORT` |
| `bundle_id` | STIX bundle `id` field |
| `status_code` | HTTP status code returned by upstream |
| `response_excerpt` | First 1 KB of upstream response body |
| `occurred_at` | Timestamp (defaults to `now()`) |
| `audit_log_id` | FK to matching `audit_log` row |

Query recent pushes:

```sql
SELECT push_target, bundle_id, status_code, occurred_at
FROM threat_intel_push
ORDER BY occurred_at DESC
LIMIT 20;
```

## Live Integration Testing

The unit tests use `MockRestServiceServer` surrogates (AC#2, AC#3). For a real end-to-end test:

1. Start a local TAXII server (e.g. `medallion`):
   ```bash
   docker run -p 5000:5000 oasis-open/medallion
   ```
2. Set `TAXII_BASE_URL=http://localhost:5000` and a valid collection ID.
3. POST to `/api/threat-intel/push/taxii` and confirm a 201 response.

For MISP:
```bash
docker compose -f docker/misp-minimal.yml up -d
```
Then set `MISP_BASE_URL` and `MISP_API_KEY` and POST to `/api/threat-intel/push/misp`.
