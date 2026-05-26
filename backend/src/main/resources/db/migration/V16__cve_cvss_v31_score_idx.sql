-- V16: index on cve.cvss_v31_score
--
-- GET /api/cve/fleet orders by cvss_v31_score DESC and filters
-- IsNotNull or GreaterThanEqual. A partial index keeps the index
-- small (only ~60% of NVD rows carry a v3.1 score) while making the
-- DESC scan a single-pass index walk.

CREATE INDEX IF NOT EXISTS cve_cvss_v31_score_idx
    ON cve (cvss_v31_score DESC)
    WHERE cvss_v31_score IS NOT NULL;
