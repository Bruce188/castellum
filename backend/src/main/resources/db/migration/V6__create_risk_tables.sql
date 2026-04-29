-- epss_score: upserted on conflict(cve_id) — daily refresh overwrites yesterday's row.
-- kev_entry: also upserted on conflict(cve_id) for idempotent re-runs.
CREATE TABLE epss_score (
  id BIGSERIAL PRIMARY KEY,
  cve_id TEXT NOT NULL UNIQUE,
  epss NUMERIC(7,6) NOT NULL,
  percentile NUMERIC(7,6) NOT NULL,
  score_date DATE NOT NULL,
  ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX epss_score_score_date_idx ON epss_score (score_date);

CREATE TABLE kev_entry (
  id BIGSERIAL PRIMARY KEY,
  cve_id TEXT NOT NULL UNIQUE,
  vendor_project TEXT,
  product TEXT,
  vulnerability_name TEXT,
  date_added DATE NOT NULL,
  short_description TEXT,
  required_action TEXT,
  due_date DATE,
  known_ransomware_campaign_use TEXT,
  notes TEXT,
  cwes TEXT,
  ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX kev_entry_date_added_idx ON kev_entry (date_added);

ALTER TABLE device ADD COLUMN criticality TEXT NOT NULL DEFAULT 'MEDIUM'
  CHECK (criticality IN ('LOW','MEDIUM','HIGH','CRITICAL'));
