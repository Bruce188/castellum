package io.castellum.cve;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditService;
import io.castellum.cve.dto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
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
    private final CveCpeMatchRepository cveCpeMatchRepository;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;
    private final int resultsPerPage;

    public NvdSyncService(NvdClient nvdClient,
                          CveRepository cveRepository,
                          CveCpeMatchRepository cveCpeMatchRepository,
                          AuditService auditService,
                          ObjectMapper objectMapper,
                          @Value("${castellum.nvd.results-per-page:2000}") int resultsPerPage) {
        this.nvdClient = nvdClient;
        this.cveRepository = cveRepository;
        this.cveCpeMatchRepository = cveCpeMatchRepository;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
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
                            int matches = upsertCve(vuln.cve());
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

    @Transactional
    protected int upsertCve(NvdCveItem item) {
        if (item == null || item.id() == null) return 0;

        String rawJson;
        try {
            rawJson = objectMapper.writeValueAsString(item);
        } catch (JsonProcessingException e) {
            rawJson = "{}";
            log.warn("re-serialize failed for {}: {}", item.id(), e.getMessage());
        }

        Cve cve = cveRepository.findByCveId(item.id()).orElseGet(Cve::new);
        cve.setCveId(item.id());
        cve.setPublished(parseInstant(item.published()));
        cve.setLastModified(parseInstant(item.lastModified()) != null
            ? parseInstant(item.lastModified()) : Instant.now());
        cve.setVulnStatus(item.vulnStatus());
        cve.setDescription(extractEnglishDescription(item));
        applyMetrics(cve, item.metrics());
        cve.setRawJson(rawJson);
        cve.setFetchedAt(Instant.now());
        Cve saved = cveRepository.save(cve);

        // Delete existing CPE matches and re-insert from current payload
        if (saved.getId() != null) {
            cveCpeMatchRepository.deleteByCveFk(saved.getId());
        }

        int matchCount = 0;
        List<NvdConfiguration> configs = item.configurations();
        if (configs != null) {
            for (NvdConfiguration cfg : configs) {
                if (cfg.nodes() == null) continue;
                for (NvdNode node : cfg.nodes()) {
                    if (node.cpeMatch() == null) continue;
                    for (NvdCpeMatch m : node.cpeMatch()) {
                        CveCpeMatch row = new CveCpeMatch();
                        row.setCveFk(saved.getId());
                        row.setCpe23Uri(m.criteria());
                        row.setVulnerable(m.vulnerable() != null ? m.vulnerable() : Boolean.FALSE);
                        row.setVersionStartIncluding(m.versionStartIncluding());
                        row.setVersionStartExcluding(m.versionStartExcluding());
                        row.setVersionEndIncluding(m.versionEndIncluding());
                        row.setVersionEndExcluding(m.versionEndExcluding());
                        cveCpeMatchRepository.save(row);
                        matchCount++;
                    }
                }
            }
        }
        return matchCount;
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

    private Instant parseInstant(String s) {
        if (s == null || s.isBlank()) return null;
        try {
            return Instant.parse(s);
        } catch (DateTimeParseException e) {
            try {
                return LocalDateTime.parse(s).toInstant(ZoneOffset.UTC);
            } catch (DateTimeParseException e2) {
                log.warn("Cannot parse NVD timestamp '{}': {}", s, e2.getMessage());
                return null;
            }
        }
    }

    private String extractEnglishDescription(NvdCveItem item) {
        if (item.descriptions() == null) return null;
        return item.descriptions().stream()
            .filter(d -> "en".equals(d.lang()))
            .map(NvdDescription::value)
            .findFirst()
            .orElse(null);
    }

    private void applyMetrics(Cve cve, NvdMetrics metrics) {
        if (metrics == null) return;
        if (metrics.cvssMetricV31() != null && !metrics.cvssMetricV31().isEmpty()) {
            NvdCvssV31.NvdCvssV31Data data = metrics.cvssMetricV31().get(0).cvssData();
            if (data != null) {
                cve.setCvssV31Score(data.baseScore());
                cve.setCvssV31Vector(data.vectorString());
            }
        }
        if (metrics.cvssMetricV30() != null && !metrics.cvssMetricV30().isEmpty()) {
            NvdCvssV30.NvdCvssV30Data data = metrics.cvssMetricV30().get(0).cvssData();
            if (data != null) {
                cve.setCvssV30Score(data.baseScore());
                cve.setCvssV30Vector(data.vectorString());
            }
        }
        if (metrics.cvssMetricV2() != null && !metrics.cvssMetricV2().isEmpty()) {
            NvdCvssV2.NvdCvssV2Data data = metrics.cvssMetricV2().get(0).cvssData();
            if (data != null) {
                cve.setCvssV2Score(data.baseScore());
                cve.setCvssV2Vector(data.vectorString());
            }
        }
    }
}
