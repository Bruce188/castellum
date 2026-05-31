package io.castellum.web;

import io.castellum.cve.Cve;
import io.castellum.cve.CveCpeMatch;
import io.castellum.cve.CveEnrichmentService;
import io.castellum.cve.CveEnrichmentService.Enrichment;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveMatcher.MatchEvidence;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.config.CacheNames;
import io.castellum.graph.CpeMapper;
import io.castellum.risk.Criticality;
import io.castellum.risk.KevEntryRepository;
import io.castellum.web.dto.CveAffectedDeviceDto;
import io.castellum.web.dto.CveCoverageDto;
import io.castellum.web.dto.CveDetailDto;
import io.castellum.web.dto.CveSummaryDto;
import org.springframework.cache.annotation.Cacheable;
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
import java.util.LinkedHashMap;
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

    /**
     * Reverse endpoint: which fleet devices are affected by a specific CVE?
     *
     * <p>Inversion of the forward fleet-match path: for each fleet service, derive its
     * CPE via {@link CpeMapper#toCpe23}, run {@link CveMatcher#findVulnerable}, and keep
     * the device if the result contains the target CVE. Version range semantics are
     * inherited from the matcher (no split-brain). Devices are deduplicated by deviceId;
     * the first matched service for each device is surfaced in the DTO.
     *
     * <p>Returns {@code 404} when the CVE id is unknown; {@code 200 + empty list} when
     * the CVE exists but no fleet device is affected (e.g. empty fleet, or no matching
     * service versions).
     *
     * <p>Cached per {@code cveId} ({@link CacheNames#CVE_AFFECTED}): the reverse fleet-match scan
     * ({@code findAll()} → per-service match) is the dominant cost of a CVE detail open, so a
     * repeat or common-case open is served from cache until a scan/feed-sync eviction (see
     * {@link io.castellum.risk.RiskCacheEvictor}, the same fleet/corpus events that invalidate
     * {@link CacheNames#CVE_FLEET}). Mirrors the {@code fleet} endpoint's proven
     * {@code @Cacheable + @PreAuthorize} ordering, so authorization is still enforced.
     */
    @GetMapping("/{cveId}/devices")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    @Cacheable(cacheNames = CacheNames.CVE_AFFECTED, key = "#cveId")
    public ResponseEntity<List<CveAffectedDeviceDto>> getAffectedDevices(
            @PathVariable String cveId) {
        // 404 on unknown CVE — distinct from 200+empty (known CVE, zero affected).
        if (cveRepository.findByCveId(cveId).isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        List<NetworkService> allServices = networkServiceRepository.findAll();
        // Map from deviceId → (service, evidence) pair — first-wins dedup.
        record ServiceEvidence(NetworkService service, CveCpeMatch matchRow) {}
        Map<Long, ServiceEvidence> deviceToEvidence = new LinkedHashMap<>();
        for (NetworkService s : allServices) {
            if (deviceToEvidence.containsKey(s.getDeviceId())) continue; // already captured
            String cpe = CpeMapper.toCpe23(s);
            if (cpe == null) continue;
            // Use findVulnerableWithEvidence so we can surface the matched CPE + range (AC1).
            cveMatcher.findVulnerableWithEvidence(cpe)
                    .stream()
                    .filter(ev -> cveId.equals(ev.cve().getCveId()))
                    .findFirst()
                    .ifPresent(ev -> deviceToEvidence.put(s.getDeviceId(), new ServiceEvidence(s, ev.matchedRow())));
        }

        if (deviceToEvidence.isEmpty()) {
            return ResponseEntity.ok(List.of());
        }

        // Batch-hydrate devices to get hostname + ipAddress.
        List<Device> devices = deviceRepository.findAllById(deviceToEvidence.keySet());
        List<CveAffectedDeviceDto> result = devices.stream()
                .map(d -> {
                    ServiceEvidence se = deviceToEvidence.get(d.getId());
                    NetworkService s = se.service();
                    CveCpeMatch row = se.matchRow();
                    return new CveAffectedDeviceDto(
                            d.getId(),
                            d.getHostname(),
                            d.getIpAddress(),
                            s.getPort(),
                            s.getName(),
                            s.getVersion(),
                            row.getCpe23Uri(),
                            formatRangeStart(row),
                            formatRangeEnd(row));
                })
                .toList();
        return ResponseEntity.ok(result);
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
    @Cacheable(cacheNames = CacheNames.CVE_FLEET,
        key = "T(java.util.Objects).hash(#page, #size, #minScore, #deviceId, #kevOnly, #sort)")
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

    // ─────────────────────────────────────────────────────────────────────
    // AC1 helpers — format version-range bounds for display
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Formats the lower version bound of a {@link CveCpeMatch} row as a human-readable
     * string (e.g. {@code "14.0 (incl.)"} or {@code "14.0 (excl.)"}); returns {@code null}
     * when no lower bound exists. Used to populate {@link CveAffectedDeviceDto#matchedRangeStart()}.
     */
    private static String formatRangeStart(CveCpeMatch row) {
        if (row.getVersionStartIncluding() != null) return row.getVersionStartIncluding() + " (incl.)";
        if (row.getVersionStartExcluding() != null) return row.getVersionStartExcluding() + " (excl.)";
        return null;
    }

    /**
     * Formats the upper version bound of a {@link CveCpeMatch} row as a human-readable
     * string (e.g. {@code "16.14 (excl.)"} or {@code "16.14 (incl.)"}); returns {@code null}
     * when no upper bound exists. Used to populate {@link CveAffectedDeviceDto#matchedRangeEnd()}.
     */
    private static String formatRangeEnd(CveCpeMatch row) {
        if (row.getVersionEndExcluding() != null) return row.getVersionEndExcluding() + " (excl.)";
        if (row.getVersionEndIncluding() != null) return row.getVersionEndIncluding() + " (incl.)";
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────
    // AC3 — corpus-coverage visibility endpoint
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Returns a brief coverage snapshot of the local NVD + KEV corpus.
     *
     * <p>Intended for the Settings / feeds panel to surface "thin corpus" hints:
     * <ul>
     *   <li>{@code totalCves} — row count of the {@code cve} table.</li>
     *   <li>{@code earliestPublishedYear} / {@code latestPublishedYear} — year span of
     *       the {@code published} column; null when no rows or no published timestamps.</li>
     *   <li>{@code kevInCorpus} — number of NVD corpus CVEs that are also in the KEV
     *       catalog (JOIN on cveId). Gives the operator "we have N KEV entries in the
     *       corpus" without loading every CVE; 0 is expected for a thin/new corpus.</li>
     *   <li>{@code thinCorpus} — derived flag: true when {@code totalCves} {@literal <} 10 000
     *       OR the year span is ≤ 1 year (corpus skewed to recent), suggesting the
     *       operator should run the full NVD backfill to get representative coverage.</li>
     * </ul>
     */
    @GetMapping("/coverage")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public CveCoverageDto coverage() {
        long totalCves = cveRepository.count();
        Integer earliestYear = cveRepository.findEarliestPublishedYear().orElse(null);
        Integer latestYear = cveRepository.findLatestPublishedYear().orElse(null);
        long kevInCorpus = kevEntryRepository.countKevInCorpus();
        boolean thin = totalCves < 10_000
                || (earliestYear != null && latestYear != null && (latestYear - earliestYear) <= 1);
        return new CveCoverageDto(totalCves, earliestYear, latestYear, kevInCorpus, thin);
    }
}
