package io.castellum.web;

import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.NoSuchElementException;

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
    public Cve getByCveId(@PathVariable String cveId) {
        return cveRepository.findByCveId(cveId)
            .orElseThrow(NoSuchElementException::new);
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public List<Cve> findByCpe(@RequestParam("cpe") String cpe) {
        return cveMatcher.findVulnerable(cpe);
    }
}
