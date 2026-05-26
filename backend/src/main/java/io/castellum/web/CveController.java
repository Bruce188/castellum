package io.castellum.web;

import io.castellum.cve.Cve;
import io.castellum.cve.CveEnrichmentService;
import io.castellum.cve.CveEnrichmentService.Enrichment;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import io.castellum.risk.KevEntry;
import io.castellum.risk.KevEntryRepository;
import io.castellum.web.dto.CveDetailDto;
import io.castellum.web.dto.CveSummaryDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/cve")
public class CveController {

    private final CveRepository cveRepository;
    private final CveMatcher cveMatcher;
    private final NetworkServiceRepository networkServiceRepository;
    private final CveEnrichmentService enrichmentService;
    private final KevEntryRepository kevEntryRepository;
    private final DeviceRepository deviceRepository;

    public CveController(CveRepository cveRepository,
                         CveMatcher cveMatcher,
                         NetworkServiceRepository networkServiceRepository,
                         CveEnrichmentService enrichmentService,
                         KevEntryRepository kevEntryRepository,
                         DeviceRepository deviceRepository) {
        this.cveRepository = cveRepository;
        this.cveMatcher = cveMatcher;
        this.networkServiceRepository = networkServiceRepository;
        this.enrichmentService = enrichmentService;
        this.kevEntryRepository = kevEntryRepository;
        this.deviceRepository = deviceRepository;
    }

    @GetMapping("/{cveId}")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public ResponseEntity<CveDetailDto> getByCveId(@PathVariable String cveId) {
        return cveRepository.findByCveId(cveId)
            .map(cve -> toDetail(cve, enrichmentService.enrichOne(cve, Criticality.MEDIUM)))
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public List<CveSummaryDto> findByCpe(@RequestParam("cpe") String cpe) {
        List<Cve> cves = cveMatcher.findVulnerable(cpe);
        Map<String, Enrichment> enrich = enrichmentService.enrich(cves, Criticality.MEDIUM);
        return cves.stream().map(c -> toSummary(c, enrich.get(c.getCveId()))).toList();
    }

    /**
     * Fleet-wide CVE listing, paginated and ordered by CVSS v3.1 score descending by
     * default. CVEs without a v3.1 score are excluded so the listing surfaces the
     * most scoring-relevant records first. Use {@code minScore} to filter to a
     * severity floor (e.g. {@code 7.0} for high/critical only).
     *
     * <p><b>v3-F1 params:</b>
     * <ul>
     *   <li>{@code kevOnly=true} narrows the result set to CVEs that appear in the
     *       CISA KEV catalog. Implementation: pull the KEV {@code cve_id} set once
     *       (catalog typically &lt; 2k rows) then use the
     *       {@code findByCveIdInAndCvssV31ScoreIsNotNull} derived query.</li>
     *   <li>{@code sort=composite} | {@code sort=epss} | {@code sort=kev} — enrichment
     *       window sort: fetch a wider candidate set (capped at 500), enrich
     *       in-memory, sort by the requested key, slice to the requested page. This
     *       path bounds per-request work; omit {@code sort} to keep the existing
     *       DB-side {@code cvssV31Score DESC, cveId ASC} ordering (backward-compat
     *       per analysis Decision 5).</li>
     * </ul>
     */
    @GetMapping("/fleet")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public Page<CveSummaryDto> fleet(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) BigDecimal minScore,
            @RequestParam(required = false) Long deviceId,
            @RequestParam(required = false) Boolean kevOnly,
            @RequestParam(required = false) String sort) {
        int clampedSize = Math.min(Math.max(size, 1), 100);
        int clampedPage = Math.max(page, 0);
        Sort sortSpec = Sort.by(Sort.Direction.DESC, "cvssV31Score")
                .and(Sort.by(Sort.Direction.ASC, "cveId"));
        Pageable pageable = PageRequest.of(clampedPage, clampedSize, sortSpec);

        Criticality criticality = (deviceId != null)
                ? deviceRepository.findById(deviceId).map(Device::getCriticality).orElse(Criticality.MEDIUM)
                : Criticality.MEDIUM;

        if (Boolean.TRUE.equals(kevOnly)) {
            Set<String> kevIds = kevEntryRepository.findAll().stream()
                    .map(KevEntry::getCveId)
                    .collect(Collectors.toSet());
            if (kevIds.isEmpty()) {
                return Page.empty(pageable);
            }
            Page<Cve> rawPage = cveRepository.findByCveIdInAndCvssV31ScoreIsNotNull(kevIds, pageable);
            Map<String, Enrichment> enrich = enrichmentService.enrich(rawPage.getContent(), criticality);
            return rawPage.map(c -> toSummary(c, enrich.get(c.getCveId())));
        }

        if ("composite".equals(sort) || "kev".equals(sort) || "epss".equals(sort)) {
            // Enrichment-window path — fetch a wider candidate set, enrich, sort
            // in memory, slice. Caps at 500 rows pre-enrichment to bound per-request
            // work (analysis Risk HIGH composite scaling).
            int windowSize = Math.min(500, clampedSize * 20);
            Pageable windowPageable = PageRequest.of(0, windowSize, sortSpec);
            Page<Cve> window = applyExistingFleetFilters(minScore, deviceId, windowPageable);
            Map<String, Enrichment> enrichMap = enrichmentService.enrich(window.getContent(), criticality);
            List<Cve> sorted = window.getContent().stream()
                    .sorted(comparatorFor(sort, enrichMap))
                    .toList();
            int start = clampedPage * clampedSize;
            int end = Math.min(start + clampedSize, sorted.size());
            List<Cve> pageContent = start < sorted.size() ? sorted.subList(start, end) : List.of();
            List<CveSummaryDto> dtos = pageContent.stream()
                    .map(c -> toSummary(c, enrichMap.get(c.getCveId())))
                    .toList();
            return new PageImpl<>(dtos, pageable, sorted.size());
        }

        // Default branch — preserves prior behaviour (CVSS DESC, cveId ASC).
        Page<Cve> rawPage = applyExistingFleetFilters(minScore, deviceId, pageable);
        Map<String, Enrichment> enrich = enrichmentService.enrich(rawPage.getContent(), criticality);
        return rawPage.map(c -> toSummary(c, enrich.get(c.getCveId())));
    }

    private Page<Cve> applyExistingFleetFilters(BigDecimal minScore, Long deviceId, Pageable pageable) {
        if (deviceId != null) {
            return fleetByDevice(deviceId, minScore, pageable);
        }
        return (minScore == null)
                ? cveRepository.findByCvssV31ScoreIsNotNull(pageable)
                : cveRepository.findByCvssV31ScoreGreaterThanEqual(minScore, pageable);
    }

    private Page<Cve> fleetByDevice(Long deviceId, BigDecimal minScore, Pageable pageable) {
        List<NetworkService> services = networkServiceRepository.findByDeviceId(deviceId);
        if (services.isEmpty()) {
            return Page.empty(pageable);
        }
        Set<Long> cveFks = new HashSet<>();
        for (NetworkService s : services) {
            if (s.getVendor() == null || s.getProduct() == null || s.getVersion() == null) {
                continue;
            }
            // CPE 2.3 requires lowercase per NIST IR 7695 §6.1.2.5; category `a` (application)
            // matches NetworkService domain (application-layer only — not OS `o` or hardware `h`).
            String cpe23 = "cpe:2.3:a:"
                    + s.getVendor().toLowerCase(java.util.Locale.ROOT) + ":"
                    + s.getProduct().toLowerCase(java.util.Locale.ROOT) + ":"
                    + s.getVersion().toLowerCase(java.util.Locale.ROOT);
            for (Cve cve : cveMatcher.findVulnerable(cpe23)) {
                cveFks.add(cve.getId());
            }
        }
        if (cveFks.isEmpty()) {
            return Page.empty(pageable);
        }
        return (minScore == null)
                ? cveRepository.findByIdInAndCvssV31ScoreIsNotNull(cveFks, pageable)
                : cveRepository.findByIdInAndCvssV31ScoreGreaterThanEqual(cveFks, minScore, pageable);
    }

    private static Comparator<Cve> comparatorFor(String sort, Map<String, Enrichment> enrich) {
        Comparator<Cve> primary;
        if ("composite".equals(sort)) {
            primary = Comparator.comparing(
                (Cve c) -> {
                    Enrichment e = enrich.get(c.getCveId());
                    return e == null ? null : e.composite();
                },
                Comparator.nullsLast(Comparator.reverseOrder()));
        } else if ("epss".equals(sort)) {
            primary = Comparator.comparing(
                (Cve c) -> {
                    Enrichment e = enrich.get(c.getCveId());
                    return e == null ? null : e.epss();
                },
                Comparator.nullsLast(Comparator.reverseOrder()));
        } else { // "kev"
            primary = Comparator.comparing(
                (Cve c) -> {
                    Enrichment e = enrich.get(c.getCveId());
                    return e != null && Boolean.TRUE.equals(e.kev());
                },
                Comparator.reverseOrder()); // true sorts first under reverse
        }
        return primary.thenComparing(Cve::getCveId); // sort-stability tiebreak
    }

    private static CveSummaryDto toSummary(Cve c, Enrichment enrichment) {
        Enrichment safe = enrichment != null ? enrichment : new Enrichment(Boolean.FALSE, null, null);
        return new CveSummaryDto(
                c.getCveId(),
                c.getPublished(),
                c.getLastModified(),
                c.getVulnStatus(),
                c.getDescription(),
                c.getCvssV31Score(),
                c.getCvssV31Vector(),
                c.getCvssV30Score(),
                c.getCvssV30Vector(),
                c.getCvssV2Score(),
                c.getCvssV2Vector(),
                c.getFetchedAt(),
                safe.kev(),
                safe.epss(),
                safe.composite());
    }

    private static CveDetailDto toDetail(Cve c, Enrichment enrichment) {
        Enrichment safe = enrichment != null ? enrichment : new Enrichment(Boolean.FALSE, null, null);
        return new CveDetailDto(
                c.getCveId(),
                c.getPublished(),
                c.getLastModified(),
                c.getVulnStatus(),
                c.getDescription(),
                c.getCvssV31Score(),
                c.getCvssV31Vector(),
                c.getCvssV30Score(),
                c.getCvssV30Vector(),
                c.getCvssV2Score(),
                c.getCvssV2Vector(),
                c.getFetchedAt(),
                c.getRawJson(),
                safe.kev(),
                safe.epss(),
                safe.composite());
    }
}
