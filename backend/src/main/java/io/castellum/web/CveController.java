package io.castellum.web;

import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
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
    public Cve getByCveId(@PathVariable String cveId) {
        return cveRepository.findByCveId(cveId)
            .orElseThrow(NoSuchElementException::new);
    }

    @GetMapping
    public List<Cve> findByCpe(@RequestParam("cpe") String cpe) {
        return cveMatcher.findVulnerable(cpe);
    }
}
