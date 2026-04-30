-- Discovery sweep audit table — records each passive-discovery sweep with FK to audit_log.
-- Append-only by service contract: sweeps are inserted at start, updated once at finish, never deleted.
CREATE TABLE discovery_sweep (
  id BIGSERIAL PRIMARY KEY,
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  source TEXT NOT NULL,
  iface TEXT,
  neighbor_count INT NOT NULL DEFAULT 0,
  device_count INT NOT NULL DEFAULT 0,
  triggered_by TEXT NOT NULL,
  audit_log_id BIGINT REFERENCES audit_log(id),
  status TEXT NOT NULL
);
CREATE INDEX idx_discovery_sweep_started ON discovery_sweep(started_at DESC);
