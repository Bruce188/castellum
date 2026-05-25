package io.castellum.web;

import io.castellum.cve.Cve;
import io.castellum.cve.CveRepository;
import io.castellum.cve.CveMatcher;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.graph.CpeMapper;
import io.castellum.risk.*;
import io.castellum.web.dto.DeviceRiskDto;
import io.castellum.web.dto.FeedsStatusDto;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
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
        record Scored(String cveId, BigDecimal composite) {}

        // First pass — collect matched CVEs per service plus a flat set of unique CVE IDs.
        // The map preserves the per-service grouping so the composite-scoring pass can walk
        // services in input order while the unique-set drives a single batch lookup per repo.
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

        // Second pass — score using the in-memory maps.
        List<Scored> all = new ArrayList<>(orderedCves.size());
        for (Cve cve : orderedCves) {
            double cvssN = CvssExtractor.normalized(cve);
            double epss = epssByCveId.getOrDefault(cve.getCveId(), BigDecimal.ZERO).doubleValue();
            boolean kev = kevSet.contains(cve.getCveId());
            RiskScore rs = CompositeScorer.score(
                new RiskInputs(cvssN, epss, kev, device.getCriticality()));
            all.add(new Scored(cve.getCveId(), rs.score()));
        }

        if (all.isEmpty()) {
            return new DeviceRiskDto(id, BigDecimal.ZERO.setScale(2), List.of());
        }
        all.sort(Comparator.comparing(Scored::composite).reversed());
        BigDecimal max = all.get(0).composite();
        List<String> top3 = all.stream()
            .map(Scored::cveId)
            .distinct()
            .limit(3)
            .toList();
        return new DeviceRiskDto(id, max, top3);
    }

}
