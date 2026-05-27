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
import io.castellum.graph.CpeMapper;
import io.castellum.risk.Criticality;
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

@RestController
@RequestMapping("/api/cve")
public class CveController {

    /**
     * Hard ceiling on the candidate set size used by the enrichment-window sort path
     * ({@code sort=composite|kev|epss}). Bounds per-request work so an attacker (or a
     * benign caller asking for a huge page) cannot trigger an unbounded scan +
     * in-memory sort. Sized to comfortably cover 5 full pages at the largest
     * {@code size=100} request (5 × 100 = 500). Promoted from magic-number per
     * review-v44 code-reviewer NB-4.
     */
    private static final int ENRICHMENT_WINDOW_CAP = 500;

    /**
     * Per-page-size multiplier used to derive the enrichment-window candidate
     * count before capping at {@link #ENRICHMENT_WINDOW_CAP}. Wider than the
     * requested page so the in-memory sort has enough candidates to surface the
     * true top-N for composite/kev/epss ordering even when many rows have null
     * enrichment values. Promoted from magic-number per review-v44 code-reviewer
     * NB-4.
     */
    private static final int ENRICHMENT_WINDOW_MULTIPLIER = 20;

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
     *   <li>{@code kevOnly=true} narrows the result set to fleet-matched CVEs that also
     *       appear in the CISA KEV catalog (respecting {@code deviceId} when present).
     *       Implementation: pull the KEV {@code cve_id} set once (catalog typically
     *       &lt; 2k rows) and the fleet-matched FK set, then intersect via the
     *       {@code findByIdInAndCveIdInAndCvssV31ScoreIsNotNull} derived query so paging
     *       stays DB-side.</li>
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
            // Intersect the CISA KEV catalog with the fleet's matched-services CVE set so
            // kevOnly returns a true subset of the fleet (respecting deviceId when present),
            // not the entire catalog. Projected query for the catalog (only cve_id column;
            // ~1.2k rows and growing — see review-v44 perf-tuner B3); fleet FKs come from the
            // same matchedCveFks path the non-kevOnly branches use. Paging stays DB-side.
            Set<String> kevIds = new HashSet<>(kevEntryRepository.findAllCveIds());
            Set<Long> fleetFks = fleetMatchedFks(deviceId);
            if (kevIds.isEmpty() || fleetFks.isEmpty()) {
                return Page.empty(pageable);
            }
            Page<Cve> rawPage = cveRepository
                    .findByIdInAndCveIdInAndCvssV31ScoreIsNotNull(fleetFks, kevIds, pageable);
            Map<String, Enrichment> enrich = enrichmentService.enrich(rawPage.getContent(), criticality);
            return rawPage.map(c -> toSummary(c, enrich.get(c.getCveId())));
        }

        if ("composite".equals(sort) || "kev".equals(sort) || "epss".equals(sort)) {
            // Enrichment-window path — fetch a wider candidate set, enrich, sort
            // in memory, slice. Capped at ENRICHMENT_WINDOW_CAP rows pre-enrichment to
            // bound per-request work (analysis Risk HIGH composite scaling).
            int windowSize = Math.min(ENRICHMENT_WINDOW_CAP, clampedSize * ENRICHMENT_WINDOW_MULTIPLIER);
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
        // No deviceId — scope to the union of CVEs matched across all fleet services.
        // Empty service list or zero matches → empty page (consistent with the per-device
        // empty-service path). Perf: service table is small; FK set is deduped in memory;
        // paging is bounded by the existing findByIdIn… queries.
        List<NetworkService> allServices = networkServiceRepository.findAll();
        if (allServices.isEmpty()) {
            return Page.empty(pageable);
        }
        Set<Long> cveFks = matchedCveFks(allServices);
        if (cveFks.isEmpty()) {
            return Page.empty(pageable);
        }
        return (minScore == null)
                ? cveRepository.findByIdInAndCvssV31ScoreIsNotNull(cveFks, pageable)
                : cveRepository.findByIdInAndCvssV31ScoreGreaterThanEqual(cveFks, minScore, pageable);
    }

    /**
     * Fleet-matched CVE foreign keys for the kevOnly intersection. Scopes to a single
     * device's services when {@code deviceId} is supplied, else the whole fleet —
     * mirroring {@link #fleetByDevice}/{@link #applyExistingFleetFilters}. Returns an
     * empty set (never the full corpus) when no services match, so the caller short-circuits
     * to an empty page.
     */
    private Set<Long> fleetMatchedFks(Long deviceId) {
        List<NetworkService> services = (deviceId != null)
                ? networkServiceRepository.findByDeviceId(deviceId)
                : networkServiceRepository.findAll();
        return services.isEmpty() ? Set.of() : matchedCveFks(services);
    }

    /**
     * Collect the union of CVE foreign-key IDs matched across a list of services,
     * using the canonical {@link CpeMapper#toCpe23} derivation. Services with a
     * null/blank name (which {@code toCpe23} maps to {@code null}) are skipped.
     */
    private Set<Long> matchedCveFks(List<NetworkService> services) {
        Set<Long> cveFks = new HashSet<>();
        for (NetworkService s : services) {
            String cpe = CpeMapper.toCpe23(s);
            if (cpe == null) continue;
            for (Cve cve : cveMatcher.findVulnerable(cpe)) {
                cveFks.add(cve.getId());
            }
        }
        return cveFks;
    }

    private Page<Cve> fleetByDevice(Long deviceId, BigDecimal minScore, Pageable pageable) {
        List<NetworkService> services = networkServiceRepository.findByDeviceId(deviceId);
        if (services.isEmpty()) {
            return Page.empty(pageable);
        }
        Set<Long> cveFks = matchedCveFks(services);
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
