package io.castellum.cve;

import io.castellum.audit.AuditService;
import io.castellum.cve.dto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class NvdSyncService {

    private static final Logger log = LoggerFactory.getLogger(NvdSyncService.class);

    /** Audit action for the operator-triggered full-corpus backfill; also gates cursor persistence. */
    private static final String FULL_BACKFILL_ACTION = "FULL_BACKFILL";

    public record SyncSummary(int slicesProcessed, int pagesFetched, int cvesUpserted, int matchesUpserted) {}

    record WindowSlice(Instant start, Instant end) {}

    private final NvdClient nvdClient;
    private final CveRepository cveRepository;
    private final CveUpsertService cveUpsertService;
    private final AuditService auditService;
    private final NvdBackfillCursorRepository backfillCursorRepository;
    private final int resultsPerPage;
    private final int backfillStartYear;

    public NvdSyncService(NvdClient nvdClient,
                          CveRepository cveRepository,
                          CveUpsertService cveUpsertService,
                          AuditService auditService,
                          NvdBackfillCursorRepository backfillCursorRepository,
                          @Value("${castellum.nvd.results-per-page:2000}") int resultsPerPage,
                          @Value("${castellum.nvd.backfill-start-year:1999}") int backfillStartYear) {
        this.nvdClient = nvdClient;
        this.cveRepository = cveRepository;
        this.cveUpsertService = cveUpsertService;
        this.auditService = auditService;
        this.backfillCursorRepository = backfillCursorRepository;
        this.resultsPerPage = resultsPerPage;
        this.backfillStartYear = backfillStartYear;
    }

    public SyncSummary bulkPull(Instant since, Instant until) throws IOException {
        return doPull(since, until, "BULK_PULL", false);
    }

    /**
     * Forces a full-corpus backfill windowed by PUBLISH date, from
     * {@code castellum.nvd.backfill-start-year} (default 1999) to now, unconditionally —
     * regardless of whether the CVE table already contains rows.
     *
     * <p>Windows by publish date (not lastModified) so modern CVEs aren't buried on the last
     * pages of NVD's single mass-re-modified lastModified window. Deliberately does NOT call
     * {@link #incrementalPull()} and does NOT consult {@code findMaxLastModified}: an explicit
     * operator-triggered backfill that bypasses the incremental short-circuit.
     */
    public SyncSummary fullBackfillPull() throws IOException {
        Instant until = Instant.now();
        Instant startYear = LocalDate.of(backfillStartYear, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant();
        // Resume from the persisted high-water window cursor when a prior backfill was
        // interrupted; a fresh or fully-completed backfill starts at the configured start year.
        Instant since = readBackfillCursor()
            .filter(cursor -> cursor.isAfter(startYear))
            .orElse(startYear);
        return doPull(since, until, FULL_BACKFILL_ACTION, true);
    }

    public SyncSummary incrementalPull() throws IOException {
        Instant until = Instant.now();
        Instant since = cveRepository.findMaxLastModified()
            .orElseGet(() -> until.minus(Duration.ofDays(120)));
        return doPull(since, until, "INCREMENTAL_PULL", false);
    }

    private SyncSummary doPull(Instant since, Instant until, String action, boolean byPublished) throws IOException {
        boolean trackCursor = FULL_BACKFILL_ACTION.equals(action);
        List<WindowSlice> slices = sliceWindow(since, until);
        int totalSlices = 0;
        int totalPages = 0;
        int totalCves = 0;
        int totalMatches = 0;

        for (WindowSlice slice : slices) {
            String windowDescription = slice.start() + "/" + slice.end();
            int startIndex = 0;
            int pagesFetched = 0;
            int cvesUpserted = 0;
            int matchesUpserted = 0;

            boolean firstPage = true;
            while (true) {
                NvdCveResponse page = byPublished
                    ? nvdClient.fetchPage(slice.start(), slice.end(), startIndex, resultsPerPage, true)
                    : nvdClient.fetchPage(slice.start(), slice.end(), startIndex, resultsPerPage);

                if (firstPage) {
                    log.info("NVD sync window={}, totalResults={}", windowDescription, page.totalResults());
                    firstPage = false;
                }

                if (page.vulnerabilities() != null) {
                    for (NvdVulnerability vuln : page.vulnerabilities()) {
                        try {
                            int matches = cveUpsertService.upsertCve(vuln.cve());
                            cvesUpserted++;
                            matchesUpserted += matches;
                        } catch (Exception e) {
                            log.warn("Failed to upsert CVE {}: {}", vuln.cve() != null ? vuln.cve().id() : "null", e.getMessage());
                        }
                    }
                }

                pagesFetched++;
                startIndex += resultsPerPage;
                if (page.totalResults() == 0 || startIndex >= page.totalResults()) {
                    break;
                }
            }

            log.info("NVD sync window={} complete: upserts={}, matches={}", windowDescription, cvesUpserted, matchesUpserted);

            auditService.recordEvent("nvd-sync", action, "cve", windowDescription,
                Map.of("startMod", slice.start().toString(),
                       "endMod", slice.end().toString(),
                       "pagesFetched", pagesFetched,
                       "cvesUpserted", cvesUpserted,
                       "matchesUpserted", matchesUpserted));

            // Persist the resume cursor after each fully-committed FULL_BACKFILL window so an
            // interrupted multi-hour backfill restarts at the last finished window instead of the
            // configured start year. Mirrors ScanExecutionService's per-chunk progress save.
            if (trackCursor) {
                saveBackfillCursor(slice.end());
            }

            totalSlices++;
            totalPages += pagesFetched;
            totalCves += cvesUpserted;
            totalMatches += matchesUpserted;
        }

        // A backfill that ran every window to completion clears the cursor so a later re-trigger
        // (for example re-seeding a wiped corpus) starts fresh from the configured start year.
        if (trackCursor) {
            clearBackfillCursor();
        }

        return new SyncSummary(totalSlices, totalPages, totalCves, totalMatches);
    }

    /** Current backfill resume point, or empty when no backfill is in progress. */
    private Optional<Instant> readBackfillCursor() {
        return backfillCursorRepository.findById(NvdBackfillCursor.SINGLETON_ID)
            .map(NvdBackfillCursor::getWindowEnd);
    }

    /** Upserts the singleton cursor row to the end of the last committed backfill window. */
    private void saveBackfillCursor(Instant windowEnd) {
        NvdBackfillCursor cursor = backfillCursorRepository.findById(NvdBackfillCursor.SINGLETON_ID)
            .orElseGet(() -> {
                NvdBackfillCursor fresh = new NvdBackfillCursor();
                fresh.setId(NvdBackfillCursor.SINGLETON_ID);
                return fresh;
            });
        cursor.setWindowEnd(windowEnd);
        backfillCursorRepository.save(cursor);
    }

    /** Resets the cursor after a completed backfill so the next run starts from the start year. */
    private void clearBackfillCursor() {
        backfillCursorRepository.findById(NvdBackfillCursor.SINGLETON_ID)
            .ifPresent(cursor -> {
                cursor.setWindowEnd(null);
                backfillCursorRepository.save(cursor);
            });
    }

    static List<WindowSlice> sliceWindow(Instant since, Instant until) {
        List<WindowSlice> slices = new ArrayList<>();
        Instant cursor = since;
        Duration maxSlice = Duration.ofDays(120);

        while (cursor.isBefore(until)) {
            Instant end = cursor.plus(maxSlice);
            if (end.isAfter(until)) {
                end = until;
            }
            slices.add(new WindowSlice(cursor, end));
            cursor = end;
        }

        if (slices.isEmpty()) {
            slices.add(new WindowSlice(since, until));
        }

        return slices;
    }
}
