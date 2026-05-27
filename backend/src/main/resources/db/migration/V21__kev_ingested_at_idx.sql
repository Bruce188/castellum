-- V21: index on kev_entry.ingested_at
--
-- GET /api/risk/feeds/status calls KevEntryRepository.findMaxIngestedAt(), a
-- MAX(ingested_at) aggregate. Without an index on ingested_at this is a full
-- table scan; with the index it is a single-pass index lookup. The sibling
-- aggregates already have supporting indexes (cve.last_modified -> V5,
-- epss_score.score_date -> V6), so this closes the last unindexed aggregate on
-- the feeds-status hot path. IF NOT EXISTS keeps the migration idempotent-safe.

CREATE INDEX IF NOT EXISTS kev_entry_ingested_at_idx
    ON kev_entry (ingested_at);
