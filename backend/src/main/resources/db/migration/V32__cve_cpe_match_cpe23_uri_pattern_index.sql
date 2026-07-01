CREATE INDEX IF NOT EXISTS cve_cpe_match_cpe23_uri_pattern_idx ON cve_cpe_match (cpe23_uri text_pattern_ops);
