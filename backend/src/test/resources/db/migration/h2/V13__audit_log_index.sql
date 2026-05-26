-- H2 mirror — drops the DESC clause to maximize cross-version H2 compatibility
CREATE INDEX IF NOT EXISTS idx_audit_log_time_action
  ON audit_log (occurred_at, action);
