package io.castellum.risk;

import io.castellum.config.CacheNames;
import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.graph.CpeMapper;
import io.castellum.web.dto.DeviceRiskDto;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Cacheable per-device composite-risk computation — the single hot path shared by
 * {@code GET /api/risk/device/{id}}, {@code GET /api/risk/devices} (batch), and
 * {@code GET /api/risk/top}.
 *
 * <p>The expensive work is the CPE→CVE match pass: for each {@link NetworkService} on the
 * device, {@link CveMatcher#findVulnerable(String)} runs a prefix scan over
 * {@code cve_cpe_match} plus a by-PK CVE load. Before this service existed, {@code /api/risk/top}
 * ran that pass <em>twice</em> per device (once for the score, once again inside a separate
 * KEV-count helper) and re-ran it on every dashboard poll. Folding score + KEV count into one
 * pass and caching the result by {@code deviceId} removes both the per-request double-scan and
 * the per-poll recompute.
 *
 * <p>Cache: {@link CacheNames#DEVICE_RISK}, keyed by {@code deviceId}. Eviction is driven by
 * the three events that can change a device's score — scan completion (new services/CVEs),
 * criticality change (device update), and feed-sync completion (new CVE/EPSS/KEV data) — and is
 * centralised in {@link RiskCacheEvictor}.
 */
@Service
public class DeviceRiskService {

    private final DeviceRepository deviceRepo;
    private final NetworkServiceRepository networkServiceRepository;
    private final CveMatcher cveMatcher;
    private final EpssScoreRepository epssRepo;
    private final KevEntryRepository kevRepo;

    public DeviceRiskService(DeviceRepository deviceRepo,
                             NetworkServiceRepository networkServiceRepository,
                             CveMatcher cveMatcher,
                             EpssScoreRepository epssRepo,
                             KevEntryRepository kevRepo) {
        this.deviceRepo = deviceRepo;
        this.networkServiceRepository = networkServiceRepository;
        this.cveMatcher = cveMatcher;
        this.epssRepo = epssRepo;
        this.kevRepo = kevRepo;
    }

    /**
     * Computes (and caches) the composite risk for one device. Returns {@link Optional#empty()}
     * when the device id does not resolve — callers map that to a 404 (single endpoint) or omit
     * the id (batch endpoint).
     *
     * <p>The {@link Optional} wrapper participates in the cache, so unknown ids cache an empty
     * result rather than re-querying every call. {@code @Cacheable} on a {@code public} method of
     * a Spring-managed bean is required for the proxy to intercept — self-invocation from within
     * this class would bypass the cache.
     */
    @Cacheable(cacheNames = CacheNames.DEVICE_RISK, key = "#deviceId")
    public Optional<DeviceRiskResult> computeRisk(long deviceId) {
        Optional<Device> device = deviceRepo.findById(deviceId);
        if (device.isEmpty()) {
            return Optional.empty();
        }
        List<NetworkService> services = networkServiceRepository.findByDeviceId(deviceId);
        return Optional.of(compute(device.get(), services));
    }

    /**
     * Cache-sharing variant for callers that already hold the {@link Device} entity (notably
     * {@code RiskController#topRisk}, which iterates {@code findAll()}). Keyed by
     * {@code device.id} into the <em>same</em> {@link CacheNames#DEVICE_RISK} cache as
     * {@link #computeRisk(long)}, so the top-N ranking, the single endpoint, and the batch
     * endpoint all hit one shared entry per device. Avoids the redundant {@code findById} the
     * id-keyed overload would perform; only the per-device {@code findByDeviceId} service lookup
     * runs (and only on a cache miss).
     *
     * <p>Returns the same {@code Optional<DeviceRiskResult>} <em>cache-value type</em> as
     * {@link #computeRisk(long)} on purpose: both overloads write the {@link CacheNames#DEVICE_RISK}
     * cache under the device-id key, so a value put by one must be readable by the other. A bare
     * {@code DeviceRiskResult} here would let a later {@code computeRisk(long)} read it as an
     * {@code Optional} (or vice versa) and {@code ClassCastException}. The caller already proved
     * the device exists, so the value is always present.
     */
    @Cacheable(cacheNames = CacheNames.DEVICE_RISK, key = "#device.id")
    public Optional<DeviceRiskResult> computeRisk(Device device) {
        List<NetworkService> services = networkServiceRepository.findByDeviceId(device.getId());
        return Optional.of(compute(device, services));
    }

    /**
     * Core scoring pass. Computes the headline (max) composite score, the top-3 contributing
     * CVE IDs, the {@code components} breakdown, and the distinct KEV-flagged CVE count — all
     * from a single CPE→CVE match traversal. Package-private and invoked only by the two
     * {@code computeRisk} cache entry points, so every score flows through the
     * {@link CacheNames#DEVICE_RISK} cache.
     */
    DeviceRiskResult compute(Device device, List<NetworkService> services) {
        record Scored(String cveId, BigDecimal composite) {}

        // Posture peak: max severity score over services that carry a non-null posture_severity.
        // Computed independently of CVE matching — a CRITICAL exposure row (e.g. docker daemon
        // on :2375) contributes risk even when no CPE/CVE matches.
        double posturePeak = 0.0;
        for (var svc : services) {
            double ps = postureScore(svc.getPostureSeverity());
            if (ps > posturePeak) posturePeak = ps;
        }

        // First pass — collect matched CVEs per service plus a flat set of unique CVE IDs.
        Map<Cve, Void> matchedCves = new LinkedHashMap<>();
        Set<String> uniqueCveIds = new HashSet<>();
        List<Cve> orderedCves = new ArrayList<>();
        for (var svc : services) {
            String cpe = CpeMapper.toCpe23(svc);
            if (cpe == null) continue;
            for (Cve cve : cveMatcher.findVulnerable(cpe)) {
                if (matchedCves.put(cve, null) == null) {
                    orderedCves.add(cve);
                }
                uniqueCveIds.add(cve.getCveId());
            }
        }

        // Two batch lookups instead of per-CVE storms.
        Map<String, BigDecimal> epssByCveId;
        Set<String> kevSet;
        if (uniqueCveIds.isEmpty()) {
            epssByCveId = Map.of();
            kevSet = Set.of();
        } else {
            epssByCveId = epssRepo.findAllByCveIdIn(uniqueCveIds).stream()
                .collect(Collectors.toMap(EpssScore::getCveId, EpssScore::getEpss,
                    (a, b) -> a, HashMap::new));
            kevSet = kevRepo.findAllByCveIdIn(uniqueCveIds).stream()
                .map(KevEntry::getCveId).collect(Collectors.toSet());
        }

        // KEV count for the device is the size of the intersection between this device's unique
        // CVE set and the KEV catalog — already materialised as kevSet above, so no second scan.
        int kevCount = kevSet.size();

        // Second pass — score using the in-memory maps. Also track max CVSS / EPSS observed
        // for the components breakdown.
        List<Scored> all = new ArrayList<>(orderedCves.size());
        double cvssMaxNormalized = 0.0;
        double epssMax = 0.0;
        boolean kevPresent = false;
        for (Cve cve : orderedCves) {
            double cvssN = CvssExtractor.normalized(cve);
            double epss = epssByCveId.getOrDefault(cve.getCveId(), BigDecimal.ZERO).doubleValue();
            boolean kev = kevSet.contains(cve.getCveId());
            if (cvssN > cvssMaxNormalized) cvssMaxNormalized = cvssN;
            if (epss > epssMax) epssMax = epss;
            if (kev) kevPresent = true;
            RiskScore rs = CompositeScorer.score(
                new RiskInputs(cvssN, epss, kev, device.getCriticality()));
            all.add(new Scored(cve.getCveId(), rs.score()));
        }

        if (all.isEmpty()) {
            // No CVE matches — score is driven entirely by posture (if present).
            BigDecimal postureScore = BigDecimal.valueOf(posturePeak).setScale(2, RoundingMode.HALF_UP);
            DeviceRiskDto empty = new DeviceRiskDto(device.getId(), postureScore, List.of(), null);
            return new DeviceRiskResult(empty, 0);
        }
        all.sort(Comparator.comparing(Scored::composite).reversed());
        // Headline score = max(CVE composite, posture peak).
        BigDecimal cveMax = all.get(0).composite();
        BigDecimal postureScoreBd = BigDecimal.valueOf(posturePeak).setScale(2, RoundingMode.HALF_UP);
        BigDecimal max = cveMax.compareTo(postureScoreBd) >= 0 ? cveMax : postureScoreBd;

        List<String> top3 = all.stream()
            .map(Scored::cveId)
            .distinct()
            .limit(3)
            .toList();

        DeviceRiskDto.ScoreComponents components = new DeviceRiskDto.ScoreComponents(
            BigDecimal.valueOf(cvssMaxNormalized * 10.0).setScale(2, RoundingMode.HALF_UP),
            BigDecimal.valueOf(epssMax).setScale(4, RoundingMode.HALF_UP),
            kevPresent,
            BigDecimal.valueOf(criticalityWeight(device.getCriticality())).setScale(2, RoundingMode.HALF_UP));

        return new DeviceRiskResult(new DeviceRiskDto(device.getId(), max, top3, components), kevCount);
    }

    /**
     * Maps a posture-severity string to a numeric score on the 0-10 scale, consistent with
     * the CVSS severity bands. Returns 0 for null/unknown values so the posture contribution
     * is silently dropped for normal (no-posture) service rows.
     */
    private static double postureScore(String severity) {
        if (severity == null) return 0.0;
        return switch (severity.toUpperCase(java.util.Locale.ROOT)) {
            case "CRITICAL" -> 9.0;
            case "HIGH"     -> 7.0;
            case "MEDIUM"   -> 5.0;
            case "LOW"      -> 3.0;
            case "INFO"     -> 1.0;
            default         -> 0.0;
        };
    }

    /** Mirror of {@link CompositeScorer}'s private critFactor table. Documented in the DTO. */
    private static double criticalityWeight(Criticality c) {
        return switch (c) {
            case LOW -> 0.0;
            case MEDIUM -> 0.25;
            case HIGH -> 0.5;
            case CRITICAL -> 1.0;
        };
    }

    /**
     * Cached unit: the wire-facing {@link DeviceRiskDto} plus the distinct KEV-flagged CVE count
     * used by {@code /api/risk/top}. Bundling both into one cached value means the top-N ranking
     * reuses the exact per-device computation (and its cache) without a second CVE-match pass.
     */
    public record DeviceRiskResult(DeviceRiskDto dto, int kevCount) {}
}
