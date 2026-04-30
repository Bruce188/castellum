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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class NvdSyncService {

    private static final Logger log = LoggerFactory.getLogger(NvdSyncService.class);

    public record SyncSummary(int slicesProcessed, int pagesFetched, int cvesUpserted, int matchesUpserted) {}

    record WindowSlice(Instant start, Instant end) {}

    private final NvdClient nvdClient;
    private final CveRepository cveRepository;
    private final CveUpsertService cveUpsertService;
    private final AuditService auditService;
    private final int resultsPerPage;

    public NvdSyncService(NvdClient nvdClient,
                          CveRepository cveRepository,
                          CveUpsertService cveUpsertService,
                          AuditService auditService,
                          @Value("${castellum.nvd.results-per-page:2000}") int resultsPerPage) {
        this.nvdClient = nvdClient;
        this.cveRepository = cveRepository;
        this.cveUpsertService = cveUpsertService;
        this.auditService = auditService;
        this.resultsPerPage = resultsPerPage;
    }

    public SyncSummary bulkPull(Instant since, Instant until) throws IOException {
        return doPull(since, until, "BULK_PULL");
    }

    public SyncSummary incrementalPull() throws IOException {
        Instant until = Instant.now();
        Instant since = cveRepository.findMaxLastModified()
            .orElseGet(() -> until.minus(Duration.ofDays(120)));
        return doPull(since, until, "INCREMENTAL_PULL");
    }

    private SyncSummary doPull(Instant since, Instant until, String action) throws IOException {
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
                NvdCveResponse page = nvdClient.fetchPage(slice.start(), slice.end(), startIndex, resultsPerPage);

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

            totalSlices++;
            totalPages += pagesFetched;
            totalCves += cvesUpserted;
            totalMatches += matchesUpserted;
        }

        return new SyncSummary(totalSlices, totalPages, totalCves, totalMatches);
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
