package io.castellum.web;

import io.castellum.threatintel.ThreatIntelService;
import io.castellum.web.dto.MispPushResponseDto;
import io.castellum.web.dto.TaxiiPushResponseDto;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/threat-intel")
public class ThreatIntelController {

    private final ThreatIntelService service;

    public ThreatIntelController(ThreatIntelService service) {
        this.service = service;
    }

    @PostMapping("/export")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> export() throws IOException {
        var result = service.exportBundle();
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result.json());
    }

    @PostMapping("/push/taxii")
    @PreAuthorize("hasRole('ADMIN')")
    public TaxiiPushResponseDto pushTaxii(
            @RequestParam(value = "collection", required = false) String collection) throws IOException {
        var r = service.pushTaxii(collection);
        return new TaxiiPushResponseDto("pushed", r.objects(), r.bundleId(), r.statusCode());
    }

    @PostMapping("/push/misp")
    @PreAuthorize("hasRole('ADMIN')")
    public MispPushResponseDto pushMisp() throws IOException {
        var r = service.pushMisp();
        return new MispPushResponseDto("pushed", r.bundleId(), r.mispEventId());
    }
}
