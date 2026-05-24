package io.castellum.web;

import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.web.dto.CveDetailDto;
import io.castellum.web.dto.CveSummaryDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

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
