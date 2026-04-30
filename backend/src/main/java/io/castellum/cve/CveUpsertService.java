package io.castellum.cve;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.cve.dto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.List;

/**
 * Owns the @Transactional boundary for upserting a single CVE plus its CPE matches.
 * Extracted from {@link NvdSyncService} to eliminate Spring's same-class self-invocation
 * hazard (CGLIB proxy is bypassed when callers invoke a @Transactional method on
 * <em>themselves</em>; routing through a separately-injected service restores the boundary
 * so a mid-loop save failure rolls back the parent CVE row plus any earlier match writes).
 */
@Service
public class CveUpsertService {

    private static final Logger log = LoggerFactory.getLogger(CveUpsertService.class);

    private final CveRepository cveRepository;
    private final CveCpeMatchRepository cveCpeMatchRepository;
    private final ObjectMapper objectMapper;

    public CveUpsertService(CveRepository cveRepository,
                            CveCpeMatchRepository cveCpeMatchRepository,
                            ObjectMapper objectMapper) {
        this.cveRepository = cveRepository;
        this.cveCpeMatchRepository = cveCpeMatchRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public int upsertCve(NvdCveItem item) {
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
