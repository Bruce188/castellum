package io.castellum.web;

import io.castellum.audit.AuditEntryDto;
import io.castellum.audit.AuditFilter;
import io.castellum.audit.AuditLog;
import io.castellum.audit.AuditLogRepository;
import io.castellum.audit.AuditQuerySpecifications;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

@RestController
@RequestMapping("/api/audit")
@Validated
public class AuditController {

    private static final int MAX_PAGE_SIZE = 500;
    private static final int CSV_ROW_CAP = 10_000;
    private static final String CSV_HEADER = "id,occurredAt,actor,action,resourceType,resourceId,payload\n";

    private final AuditLogRepository repository;

    public AuditController(AuditLogRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public Page<AuditEntryDto> list(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant since,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant until,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String actor,
            @RequestParam(required = false) String resourceType,
            @PageableDefault(size = 50, sort = "occurredAt", direction = Sort.Direction.DESC) Pageable pageable) {
        int effSize = Math.min(pageable.getPageSize(), MAX_PAGE_SIZE);
        Pageable effective = PageRequest.of(pageable.getPageNumber(), effSize, pageable.getSort());
        var spec = AuditQuerySpecifications.build(new AuditFilter(since, until, action, actor, resourceType));
        return repository.findAll(spec, effective).map(AuditEntryDto::from);
    }

    @GetMapping(value = "/csv", produces = "text/csv")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<StreamingResponseBody> exportCsv(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant since,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant until,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String actor,
            @RequestParam(required = false) String resourceType) {
        var filter = new AuditFilter(since, until, action, actor, resourceType);
        var spec = AuditQuerySpecifications.build(filter);
        long total = repository.count(spec);
        if (total > CSV_ROW_CAP) {
            String body = "{\"error\":\"csv_cap_exceeded\",\"limit\":" + CSV_ROW_CAP + ",\"filteredCount\":" + total + "}";
            return ResponseEntity.status(413)
                .header("Content-Type", "application/json")
                .body(out -> out.write(body.getBytes(StandardCharsets.UTF_8)));
        }
        StreamingResponseBody stream = out -> {
            try (var writer = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8))) {
                writer.write(CSV_HEADER);
                Sort sort = Sort.by(Sort.Direction.DESC, "occurredAt");
                for (AuditLog row : repository.findAll(spec, sort)) {
                    writer.write(csvLine(row));
                }
            }
        };
        return ResponseEntity.ok()
            .header("Content-Type", "text/csv; charset=UTF-8")
            .header("Content-Disposition", "attachment; filename=\"audit-log.csv\"")
            .body(stream);
    }

    private static String csvLine(AuditLog row) {
        return String.join(",",
            csvEscape(row.getId()),
            csvEscape(row.getOccurredAt()),
            csvEscape(row.getActor()),
            csvEscape(row.getAction()),
            csvEscape(row.getResourceType()),
            csvEscape(row.getResourceId()),
            csvEscape(row.getPayload())
        ) + "\n";
    }

    static String csvEscape(Object v) {
        if (v == null) return "";
        String s = v.toString();
        if (s.indexOf(',') >= 0 || s.indexOf('"') >= 0 || s.indexOf('\n') >= 0) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }
}
