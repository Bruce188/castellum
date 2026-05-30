package io.castellum.web;

import io.castellum.threatintel.ExportJob;
import io.castellum.threatintel.ExportJobService;
import io.castellum.threatintel.ThreatIntelService;
import io.castellum.web.dto.MispPushResponseDto;
import io.castellum.web.dto.TaxiiPushResponseDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

@RestController
@RequestMapping("/api/threat-intel")
public class ThreatIntelController {

    private final ThreatIntelService service;
    private final ExportJobService exportJobService;

    @Autowired
    public ThreatIntelController(ThreatIntelService service, ExportJobService exportJobService) {
        this.service = service;
        this.exportJobService = exportJobService;
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

    // ── async export endpoints ──────────────────────────────────────────────────

    /**
     * Submit an async export job. Returns 202 Accepted with jobId and initial status.
     */
    @PostMapping("/export/async")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AsyncSubmitResponse> submitExportAsync() {
        String jobId = exportJobService.submit();
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(new AsyncSubmitResponse(jobId, ExportJob.Status.PENDING.name()));
    }

    record AsyncSubmitResponse(String jobId, String status) {}

    /**
     * Poll an async export job.
     * <ul>
     *   <li>DONE → 200 with streaming JSON file body (application/json)
     *   <li>PENDING / RUNNING / FAILED → 200 with status JSON
     *   <li>Unknown id → 404
     * </ul>
     */
    @GetMapping("/export/async/{jobId}")
    @PreAuthorize("hasAnyRole('ADMIN','VIEWER')")
    public ResponseEntity<StreamingResponseBody> getExportAsync(@PathVariable String jobId) {
        Optional<ExportJob> found = exportJobService.get(jobId);
        if (found.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        ExportJob job = found.get();

        if (job.status() == ExportJob.Status.DONE) {
            Path file = Path.of(job.filePath());
            StreamingResponseBody stream = (OutputStream out) -> Files.copy(file, out);
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(stream);
        }

        // PENDING / RUNNING / FAILED — return status JSON
        String json = buildStatusJson(job);
        StreamingResponseBody stream = (OutputStream out) ->
                out.write(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(stream);
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    private static String buildStatusJson(ExportJob job) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"id\":\"").append(job.id()).append("\"");
        sb.append(",\"status\":\"").append(job.status().name()).append("\"");
        if (job.error() != null) {
            sb.append(",\"error\":\"").append(jsonEscape(job.error())).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private static String jsonEscape(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
