-- V16 (H2 mirror): index on cve.cvss_v31_score
--
-- H2 does not support partial indexes (WHERE clause on CREATE INDEX
-- raises a syntax error), so the H2 mirror uses an unfiltered index.
-- Functionally equivalent for derived-query path planning; size cost
-- is negligible in the test fixture.

CREATE INDEX IF NOT EXISTS cve_cvss_v31_score_idx
    ON cve (cvss_v31_score);
