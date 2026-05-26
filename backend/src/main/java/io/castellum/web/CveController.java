package io.castellum.web;

import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
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
import java.util.List;

@RestController
@RequestMapping("/api/cve")
public class CveController {

    private final CveRepository cveRepository;
    private final CveMatcher cveMatcher;

    public CveController(CveRepository cveRepository, CveMatcher cveMatcher) {
        this.cveRepository = cveRepository;
        this.cveMatcher = cveMatcher;
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
            @RequestParam(required = false) BigDecimal minScore) {
        int clampedSize = Math.min(Math.max(size, 1), 100);
        int clampedPage = Math.max(page, 0);
        Sort sort = Sort.by(Sort.Direction.DESC, "cvssV31Score")
                .and(Sort.by(Sort.Direction.ASC, "cveId"));
        Pageable pageable = PageRequest.of(clampedPage, clampedSize, sort);
        Page<Cve> result = (minScore == null)
                ? cveRepository.findByCvssV31ScoreIsNotNull(pageable)
                : cveRepository.findByCvssV31ScoreGreaterThanEqual(minScore, pageable);
        return result.map(CveController::toSummary);
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
