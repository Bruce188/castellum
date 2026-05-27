-- V21 (H2 mirror): index on kev_entry.ingested_at
--
-- Mirror of the production V21 migration. H2 supports plain (unfiltered) btree
-- indexes with identical syntax here, so no dialect adjustment is needed beyond
-- the comment header. Backs MAX(ingested_at) for GET /api/risk/feeds/status.

CREATE INDEX IF NOT EXISTS kev_entry_ingested_at_idx
    ON kev_entry (ingested_at);
