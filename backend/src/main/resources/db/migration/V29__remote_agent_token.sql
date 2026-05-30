CREATE TABLE remote_agent_token (
  id BIGSERIAL PRIMARY KEY,
  label VARCHAR(128) NOT NULL,
  token_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by VARCHAR(64),
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  revoked_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ
);
CREATE INDEX idx_remote_agent_token_revoked ON remote_agent_token(revoked);
