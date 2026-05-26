package io.castellum.web;

import io.castellum.cve.Cve;
import io.castellum.cve.CveRepository;
import io.castellum.cve.CveMatcher;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.graph.CpeMapper;
import io.castellum.risk.*;
import io.castellum.web.dto.DeviceRiskDto;
import io.castellum.web.dto.FeedsStatusDto;
import io.castellum.web.dto.TopRiskDeviceDto;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/risk")
public class RiskController {

    private static final int TOP_DEFAULT_N = 10;
    private static final int TOP_MAX_N = 100;

    private final CveRepository cveRepo;
    private final DeviceRepository deviceRepo;
    private final EpssScoreRepository epssRepo;
    private final KevEntryRepository kevRepo;
    private final NetworkServiceRepository networkServiceRepository;
    private final CveMatcher cveMatcher;

    public RiskController(CveRepository cveRepo, DeviceRepository deviceRepo,
                           EpssScoreRepository epssRepo, KevEntryRepository kevRepo,
                           NetworkServiceRepository networkServiceRepository,
                           CveMatcher cveMatcher) {
        this.cveRepo = cveRepo;
        this.deviceRepo = deviceRepo;
        this.epssRepo = epssRepo;
        this.kevRepo = kevRepo;
        this.networkServiceRepository = networkServiceRepository;
        this.cveMatcher = cveMatcher;
    }

    @GetMapping("/score")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public RiskScore score(@RequestParam("cve") String cveId, @RequestParam("device") long deviceId) {
        Cve cve = cveRepo.findByCveId(cveId)
            .orElseThrow(() -> new NoSuchElementException("CVE not found: " + cveId));
        Device device = deviceRepo.findById(deviceId)
            .orElseThrow(() -> new NoSuchElementException("Device not found: " + deviceId));
        double cvssN = CvssExtractor.normalized(cve);
        double epss = epssRepo.findByCveId(cveId).map(e -> e.getEpss().doubleValue()).orElse(0.0);
        boolean kev = kevRepo.existsByCveId(cveId);
        var inputs = new RiskInputs(cvssN, epss, kev, device.getCriticality());
        return CompositeScorer.score(inputs);
    }

    @GetMapping("/feeds/status")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public FeedsStatusDto feedsStatus() {
        long epssCount = epssRepo.count();
        var epssMaxDate = epssRepo.findMaxScoreDate().orElse(null);
        long kevCount = kevRepo.count();
        var kevMaxIngest = kevRepo.findMaxIngestedAt().orElse(null);
        long nvdCount = cveRepo.count();
        var nvdLastModified = cveRepo.findMaxLastModified().orElse(null);
        return new FeedsStatusDto(
            new FeedsStatusDto.EpssStatus(epssMaxDate, epssCount),
            new FeedsStatusDto.KevStatus(kevMaxIngest, kevCount),
            new FeedsStatusDto.NvdStatus(nvdLastModified, nvdCount));
    }

    @GetMapping("/device/{id}")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public DeviceRiskDto deviceRisk(@PathVariable long id) {
        Device device = deviceRepo.findById(id)
            .orElseThrow(() -> new NoSuchElementException("Device not found: " + id));
        var services = networkServiceRepository.findByDeviceId(id);
        return computeDeviceRisk(device, services);
    }

    /**
     * Returns the top-N at-risk devices ordered by composite score (descending).
     *
     * <p>{@code n} is clamped to {@code [1, 100]}; default 10. The implementation walks every
     * device in the fleet, computes the same composite-score pipeline used by
     * {@link #deviceRisk(long)}, sorts, and truncates. This is acceptable for the typical
     * pilot-scale fleet (≤ a few thousand devices) — pagination is a follow-up.
     *
     * <p>Performance note: services are batch-loaded per device via the existing
     * {@code findByDeviceId} repository call. A future optimisation could batch-load all
     * services in one call and group in memory, but this is not currently a hotspot.
     *
     * @param n requested page size; clamped to {@code [1, 100]}, default 10.
     * @return  list of {@link TopRiskDeviceDto}, ordered by score descending; ties broken by deviceId asc.
     */
    @GetMapping("/top")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public List<TopRiskDeviceDto> topRisk(@RequestParam(value = "n", required = false) Integer n) {
        int requested = n == null ? TOP_DEFAULT_N : n;
        if (requested < 1) requested = 1;
        if (requested > TOP_MAX_N) requested = TOP_MAX_N;
        final int clampedN = requested;

        var devices = deviceRepo.findAll();
        if (devices.isEmpty()) return List.of();

        record Ranked(TopRiskDeviceDto dto, BigDecimal score) {}
        List<Ranked> all = new ArrayList<>(devices.size());
        for (Device d : devices) {
            var services = networkServiceRepository.findByDeviceId(d.getId());
            DeviceRiskDto risk = computeDeviceRisk(d, services);
            int kevCount = countKevForDevice(services);
            TopRiskDeviceDto dto = new TopRiskDeviceDto(
                d.getId(),
                d.getHostname(),
                d.getIpAddress(),
                d.getCriticality(),
                risk.score(),
                kevCount);
            all.add(new Ranked(dto, risk.score()));
        }
        all.sort(Comparator
            .comparing(Ranked::score, Comparator.reverseOrder())
            .thenComparing(r -> r.dto().deviceId()));
        return all.stream().limit(clampedN).map(Ranked::dto).toList();
    }

    /**
     * Shared core that powers both {@link #deviceRisk(long)} and {@link #topRisk(Integer)}.
     * Computes the per-CVE composite-score pass, returns the headline (max) score plus the
     * top-3 contributing CVE IDs, and the {@code components} breakdown (CVSS_max, EPSS_max,
     * KEV_present, criticality_weight) derived across the device's CVE set.
     */
    private DeviceRiskDto computeDeviceRisk(Device device, List<NetworkService> services) {
        record Scored(String cveId, BigDecimal composite) {}

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
            return new DeviceRiskDto(device.getId(), BigDecimal.ZERO.setScale(2), List.of(), null);
        }
        all.sort(Comparator.comparing(Scored::composite).reversed());
        BigDecimal max = all.get(0).composite();
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

        return new DeviceRiskDto(device.getId(), max, top3, components);
    }

    private int countKevForDevice(List<NetworkService> services) {
        Set<String> uniqueCveIds = new HashSet<>();
        for (var svc : services) {
            String cpe = CpeMapper.toCpe23(svc);
            if (cpe == null) continue;
            for (Cve cve : cveMatcher.findVulnerable(cpe)) {
                uniqueCveIds.add(cve.getCveId());
            }
        }
        if (uniqueCveIds.isEmpty()) return 0;
        return kevRepo.findAllByCveIdIn(uniqueCveIds).size();
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
}
