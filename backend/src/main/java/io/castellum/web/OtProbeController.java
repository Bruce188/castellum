package io.castellum.web;

import io.castellum.ot.OtFingerprintService;
import io.castellum.ot.OtFingerprintService.OtProbeResult;
import io.castellum.web.dto.OtProbeRequest;
import io.castellum.web.dto.OtProbeResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST endpoint for OT/ICS read-only fingerprinting.
 *
 * <p>POST /api/ot-probe → 200 success, 400 validation, 502 unreachable/decode,
 * 504 timeout, 501 not-implemented. Exception mapping via {@link GlobalExceptionHandler}.
 */
@RestController
public class OtProbeController {

    private final OtFingerprintService service;

    public OtProbeController(OtFingerprintService service) {
        this.service = service;
    }

    @PostMapping("/api/ot-probe")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<OtProbeResponse> probe(@Valid @RequestBody OtProbeRequest request) {
        OtProbeResult result = service.probe(request.host(), request.port(), request.protocol());
        OtProbeResponse response = new OtProbeResponse(
            result.host(),
            result.port(),
            result.protocol(),
            result.vendor(),
            result.product(),
            result.version(),
            result.rawFields(),
            result.deviceId(),
            result.serviceId(),
            result.observedAt()
        );
        return ResponseEntity.ok(response);
    }
}
