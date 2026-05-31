package io.castellum.cve;

import io.castellum.config.CacheNames;
import io.castellum.cve.CveEnrichmentService.Enrichment;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.graph.CpeMapper;
import io.castellum.risk.Criticality;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Page-independent fleet-sort window for the enrichment-window sort path
 * ({@code sort=composite|kev|epss}) of {@code GET /api/cve/fleet}.
 *
 * <p><b>Why a separate bean.</b> The expensive part of the sort path — fleet CPE→CVE
 * scan, a bounded ({@value #ENRICHMENT_WINDOW_CAP}-row) DB query, batch enrichment, and
 * an in-memory sort — depends only on {@code (minScore, deviceId, sort)} and the device's
 * {@link Criticality}; it does NOT depend on the requested page. The controller's
 * {@code @Cacheable(CVE_FLEET)} is keyed per page, so without this bean each first-visit
 * to a new page re-ran the whole scan+enrich+sort. Caching the sorted window here, keyed
 * by {@code (minScore, deviceId, sort)}, lets every page of one query reuse a single
 * computation; the controller then merely slices the page.
 *
 * <p>This must be its OWN bean (not a private method on the controller): a self-invoked
 * {@code @Cacheable} method is not routed through the Spring proxy and would never cache.
 *
 * <p>Eviction mirrors {@code CVE_FLEET}: the same scan/corpus events ({@code onScanComplete},
 * {@code onFeedSyncComplete}) that invalidate the fleet listing invalidate this window —
 * see {@code RiskCacheEvictor}.
 */
@Service
public class FleetCveWindowService {

    /**
     * Hard ceiling on the candidate set size fetched before enrichment + in-memory sort.
     * Bounds per-request work so a huge fleet cannot trigger an unbounded scan + sort.
     * Sized to comfortably cover five full pages at the largest {@code size=100} request
     * (5 × 100 = 500).
     */
    private static final int ENRICHMENT_WINDOW_CAP = 500;

    private final NetworkServiceRepository networkServiceRepository;
    private final CveMatcher cveMatcher;
    private final CveRepository cveRepository;
    private final CveEnrichmentService enrichmentService;

    public FleetCveWindowService(NetworkServiceRepository networkServiceRepository,
                                 CveMatcher cveMatcher,
                                 CveRepository cveRepository,
                                 CveEnrichmentService enrichmentService) {
        this.networkServiceRepository = networkServiceRepository;
        this.cveMatcher = cveMatcher;
        this.cveRepository = cveRepository;
        this.enrichmentService = enrichmentService;
    }

    /**
     * Page-independent sorted window plus the enrichment map used to build it. The
     * controller slices {@link #sorted()} per page and reads {@link #enrich()} to
     * populate each row's KEV/EPSS/composite fields without re-enriching.
     */
    public record SortedWindow(List<Cve> sorted, Map<String, Enrichment> enrich) {}

    /**
     * Compute (or return the cached) page-independent sorted window for the given
     * {@code (minScore, deviceId, sort)} tuple. The {@code criticality} feeds composite
     * scoring; it is derived by the caller from the device and is intentionally NOT part
     * of the cache key (it is a deterministic function of {@code deviceId}).
     */
    @Cacheable(cacheNames = CacheNames.CVE_FLEET_WINDOW,
        key = "T(java.util.Objects).hash(#minScore, #deviceId, #sort)")
    public SortedWindow window(BigDecimal minScore, Long deviceId, String sort, Criticality criticality) {
        // 1. Matched CVE FK set — scoped to one device's services when deviceId is present,
        //    else the union across the whole fleet. Empty fleet → empty window.
        List<NetworkService> services = (deviceId != null)
                ? networkServiceRepository.findByDeviceId(deviceId)
                : networkServiceRepository.findAll();
        if (services.isEmpty()) {
            return new SortedWindow(List.of(), Map.of());
        }
        Set<Long> fks = new HashSet<>();
        for (NetworkService s : services) {
            String cpe = CpeMapper.toCpe23(s);
            if (cpe == null) continue;
            for (Cve cve : cveMatcher.findVulnerable(cpe)) {
                fks.add(cve.getId());
            }
        }
        // 2. No matched CVEs → empty window (never the full corpus).
        if (fks.isEmpty()) {
            return new SortedWindow(List.of(), Map.of());
        }

        // 3. Fixed, page-independent window pageable (always page 0, capped size).
        Sort sortSpec = Sort.by(Sort.Direction.DESC, "cvssV31Score")
                .and(Sort.by(Sort.Direction.ASC, "cveId"));
        Pageable windowPageable = PageRequest.of(0, ENRICHMENT_WINDOW_CAP, sortSpec);
        Page<Cve> window = (minScore == null)
                ? cveRepository.findByIdInAndCvssV31ScoreIsNotNull(fks, windowPageable)
                : cveRepository.findByIdInAndCvssV31ScoreGreaterThanEqual(fks, minScore, windowPageable);

        // 4. Batch-enrich the window once.
        Map<String, Enrichment> enrich = enrichmentService.enrich(window.getContent(), criticality);

        // 5. Sort in memory by the requested key (composite/epss/kev) with a cveId tiebreak.
        List<Cve> sorted = window.getContent().stream()
                .sorted(comparatorFor(sort, enrich))
                .toList();

        // 6. Hand back the page-independent sorted window + its enrichment map.
        return new SortedWindow(sorted, enrich);
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
}
