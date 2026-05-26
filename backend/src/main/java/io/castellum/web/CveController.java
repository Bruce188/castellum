package io.castellum.web;

import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.web.dto.CveDetailDto;
import io.castellum.web.dto.CveSummaryDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/cve")
public class CveController {

    private final CveRepository cveRepository;
    private final CveMatcher cveMatcher;
    private final NetworkServiceRepository networkServiceRepository;

    public CveController(CveRepository cveRepository,
                         CveMatcher cveMatcher,
                         NetworkServiceRepository networkServiceRepository) {
        this.cveRepository = cveRepository;
        this.cveMatcher = cveMatcher;
        this.networkServiceRepository = networkServiceRepository;
    }

    @GetMapping("/{cveId}")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public ResponseEntity<CveDetailDto> getByCveId(@PathVariable String cveId) {
        return cveRepository.findByCveId(cveId)
            .map(CveController::toDetail)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public List<CveSummaryDto> findByCpe(@RequestParam("cpe") String cpe) {
        return cveMatcher.findVulnerable(cpe).stream().map(CveController::toSummary).toList();
    }

    /**
     * Fleet-wide CVE listing, paginated and ordered by CVSS v3.1 score descending.
     * CVEs without a v3.1 score are excluded so the listing surfaces the most
     * scoring-relevant records first. Use {@code minScore} to filter to a severity
     * floor (e.g. {@code 7.0} for high/critical only).
     */
    @GetMapping("/fleet")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public Page<CveSummaryDto> fleet(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) BigDecimal minScore,
            @RequestParam(required = false) Long deviceId) {
        int clampedSize = Math.min(Math.max(size, 1), 100);
        int clampedPage = Math.max(page, 0);
        Sort sort = Sort.by(Sort.Direction.DESC, "cvssV31Score")
                .and(Sort.by(Sort.Direction.ASC, "cveId"));
        Pageable pageable = PageRequest.of(clampedPage, clampedSize, sort);
        Page<Cve> result = (deviceId == null)
                ? ((minScore == null)
                    ? cveRepository.findByCvssV31ScoreIsNotNull(pageable)
                    : cveRepository.findByCvssV31ScoreGreaterThanEqual(minScore, pageable))
                : fleetByDevice(deviceId, minScore, pageable);
        return result.map(CveController::toSummary);
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

    private static CveSummaryDto toSummary(Cve c) {
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
                c.getFetchedAt());
    }

    private static CveDetailDto toDetail(Cve c) {
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
                c.getRawJson());
    }
}
