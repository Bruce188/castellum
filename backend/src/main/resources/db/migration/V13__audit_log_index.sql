-- feat/audit-log-viewer: composite index for filter + sort path
-- Query shape: WHERE occurred_at >= ? AND occurred_at < ? AND action = ? ORDER BY occurred_at DESC
CREATE INDEX IF NOT EXISTS idx_audit_log_time_action
  ON audit_log (occurred_at DESC, action);
