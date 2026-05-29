package io.castellum.web.dto;

/**
 * Read-only DTO for {@code GET /api/cve/coverage}.
 *
 * <p>Surfaces the corpus-coverage snapshot used by the Settings / feeds panel to
 * explain "thin corpus" conditions (near-duplicate CVE lists, 0-KEV badges) without
 * alarming the operator. When {@link #thinCorpus()} is true the UI should show a hint
 * pointing to the "Full NVD backfill" action ({@code POST /api/admin/full-backfill}).
 *
 * @param totalCves           row count of the {@code cve} table; 0 on empty corpus.
 * @param earliestPublishedYear earliest year value of the {@code published} column; null
 *                            when no CVE has a published timestamp.
 * @param latestPublishedYear   latest year value of the {@code published} column; null
 *                            when no CVE has a published timestamp.
 * @param kevInCorpus         number of KEV catalog entries whose {@code cve_id} matches
 *                            a row in the corpus; 0 is expected for a thin/new corpus.
 * @param thinCorpus          true when the corpus appears thin: fewer than 10 000 CVEs
 *                            OR the published year span is ≤ 1 (skewed to one recent year).
 *                            Signals the operator to run the full NVD backfill.
 */
public record CveCoverageDto(
        long totalCves,
        Integer earliestPublishedYear,
        Integer latestPublishedYear,
        long kevInCorpus,
        boolean thinCorpus) {}
