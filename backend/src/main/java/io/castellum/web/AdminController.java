package io.castellum.web;

import io.castellum.admin.InitialSyncService;
import io.castellum.audit.AuditService;
import io.castellum.web.dto.InitialSyncRequest;
import io.castellum.web.dto.InitialSyncResponse;
import io.castellum.web.dto.SyncStatusResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final InitialSyncService initialSyncService;
    private final AuditService auditService;

    public AdminController(InitialSyncService initialSyncService, AuditService auditService) {
        this.initialSyncService = initialSyncService;
        this.auditService = auditService;
    }

    /**
     * Returns the current sync in-flight status.
     *
     * <p>ADMIN-only, read-only. No audit row is emitted — reads are silent.
     */
    @GetMapping("/sync/status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<SyncStatusResponse> syncStatus() {
        return ResponseEntity.ok(new SyncStatusResponse(
                initialSyncService.isInFlight(),
                initialSyncService.getStartedAt()));
    }

    /**
     * Triggers an initial data sync of NVD, EPSS, and KEV feeds.
     *
     * <p>ADMIN-only. Returns 202 immediately; the actual ingest runs on the
     * {@code initialSyncTaskExecutor} thread pool. The {@code INITIAL_SYNC_TRIGGERED}
     * audit row is emitted <em>before</em> dispatching the background job so operators
     * see every click regardless of in-flight guard outcome.
     */
    @PostMapping("/initial-sync")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<InitialSyncResponse> trigger(
            @RequestBody(required = false) InitialSyncRequest body) {

        String actor = SecurityContextHolder.getContext().getAuthentication().getName();
        InitialSyncRequest req = (body == null) ? InitialSyncRequest.defaults() : body;

        // Emit the audit row BEFORE dispatch — operators see every click.
        auditService.recordEvent(actor, "INITIAL_SYNC_TRIGGERED", "initial-sync", "global",
            Map.of("since", String.valueOf(req.effectiveSince()),
                   "until", String.valueOf(req.effectiveUntil())));

        InitialSyncResponse response = initialSyncService.trigger(req, actor);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }
}
