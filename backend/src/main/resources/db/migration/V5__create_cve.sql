-- Updateable on conflict(cve_id) — NVD revises CVEs over time. Upserts via INSERT ... ON CONFLICT
-- or JpaRepository.save() after findByCveId. This is the deliberate departure from audit_log's append-only contract.
CREATE TABLE cve (
  id BIGSERIAL PRIMARY KEY,
  cve_id TEXT NOT NULL UNIQUE,
  published TIMESTAMPTZ,
  last_modified TIMESTAMPTZ NOT NULL,
  vuln_status TEXT,
  description TEXT,
  cvss_v31_score NUMERIC(3,1),
  cvss_v31_vector TEXT,
  cvss_v30_score NUMERIC(3,1),
  cvss_v30_vector TEXT,
  cvss_v2_score NUMERIC(3,1),
  cvss_v2_vector TEXT,
  raw_json TEXT NOT NULL,
  fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX cve_last_modified_idx ON cve (last_modified);

CREATE TABLE cve_cpe_match (
  id BIGSERIAL PRIMARY KEY,
  cve_fk BIGINT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
  cpe23_uri TEXT NOT NULL,
  vulnerable BOOLEAN NOT NULL,
  version_start_including TEXT,
  version_start_excluding TEXT,
  version_end_including TEXT,
  version_end_excluding TEXT
);
CREATE INDEX cve_cpe_match_cpe23_uri_idx ON cve_cpe_match (cpe23_uri);
CREATE INDEX cve_cpe_match_cve_fk_idx ON cve_cpe_match (cve_fk);
