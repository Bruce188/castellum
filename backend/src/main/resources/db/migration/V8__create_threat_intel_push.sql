CREATE TABLE threat_intel_push (
  id BIGSERIAL PRIMARY KEY,
  push_target TEXT NOT NULL CHECK (push_target IN ('TAXII','MISP','EXPORT')),
  bundle_id TEXT NOT NULL,
  status_code INT,
  response_excerpt TEXT,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  audit_log_id BIGINT REFERENCES audit_log(id)
);
CREATE INDEX threat_intel_push_target_idx ON threat_intel_push (push_target);
CREATE INDEX threat_intel_push_bundle_id_idx ON threat_intel_push (bundle_id);
