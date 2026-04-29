package io.castellum.web;

import io.castellum.cve.Cve;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.*;
import io.castellum.web.dto.FeedsStatusDto;
import org.springframework.web.bind.annotation.*;

import java.util.NoSuchElementException;

@RestController
@RequestMapping("/api/risk")
public class RiskController {

    private final CveRepository cveRepo;
    private final DeviceRepository deviceRepo;
    private final EpssScoreRepository epssRepo;
    private final KevEntryRepository kevRepo;

    public RiskController(CveRepository cveRepo, DeviceRepository deviceRepo,
                           EpssScoreRepository epssRepo, KevEntryRepository kevRepo) {
        this.cveRepo = cveRepo;
        this.deviceRepo = deviceRepo;
        this.epssRepo = epssRepo;
        this.kevRepo = kevRepo;
    }

    @GetMapping("/score")
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
    public FeedsStatusDto feedsStatus() {
        long epssCount = epssRepo.count();
        var epssMaxDate = epssRepo.findMaxScoreDate().orElse(null);
        long kevCount = kevRepo.count();
        var kevMaxIngest = kevRepo.findMaxIngestedAt().orElse(null);
        return new FeedsStatusDto(
            new FeedsStatusDto.EpssStatus(epssMaxDate, epssCount),
            new FeedsStatusDto.KevStatus(kevMaxIngest, kevCount));
    }

}
