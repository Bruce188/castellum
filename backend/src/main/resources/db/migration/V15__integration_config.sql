-- V15: integration_config — TAXII + MISP user-managed settings with
-- encrypted-at-rest credentials.
--
-- Each row is keyed by integration_type ('TAXII' or 'MISP'). Non-secret
-- config (URL, collection-id, etc.) lives in config_json as JSON text.
-- Secrets (TAXII password, MISP API key) live in encrypted_credentials as
-- AES-256-GCM ciphertext (12-byte IV prefix + ciphertext + 16-byte tag).
-- Encryption key comes from CASTELLUM_INTEGRATION_KEY (base64 AES-256).
--
-- last_push_at / last_push_status track the most recent push attempt and
-- whether it succeeded; surfaced in the Settings → Integrations UI.

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
