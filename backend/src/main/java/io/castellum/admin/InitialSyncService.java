package io.castellum.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditFilter;
import io.castellum.audit.AuditLog;
import io.castellum.audit.AuditLogRepository;
import io.castellum.audit.AuditQuerySpecifications;
import io.castellum.audit.AuditService;
import io.castellum.cve.NvdSyncService;
import io.castellum.risk.EpssIngestionService;
import io.castellum.risk.KevIngestionService;
import io.castellum.web.dto.InitialSyncRequest;
import io.castellum.web.dto.InitialSyncResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Orchestrates the one-click initial data-sync background job.
 *
 * <p>An {@code AtomicBoolean inFlight} gate ensures at most one sync runs at a time.
 * Concurrent callers receive a 202 with {@code status:"already-running"} and the
 * {@code startedAt} timestamp of the in-flight job.
 *
 * <p>The background task invokes NVD bulk pull, EPSS ingest, and KEV ingest
 * <em>sequentially</em> with per-feed failure isolation: a failure in one feed does NOT
 * prevent the remaining feeds from running.  The {@code finally} block always clears
 * {@code inFlight} so future syncs are not permanently locked out.
 *
 * <p>On completion (success or partial failure) a terminal {@code INITIAL_SYNC_COMPLETED}
 * audit event is emitted. After restart, {@link #getLastCompletedAt()} and
 * {@link #getLastError()} reconstruct from the audit log lazily.
 */
@Service
public class InitialSyncService {

    private static final Logger log = LoggerFactory.getLogger(InitialSyncService.class);

    private final ThreadPoolTaskExecutor executor;
    private final NvdSyncService nvdSyncService;
    private final EpssIngestionService epssIngestionService;
    private final KevIngestionService kevIngestionService;
    private final AuditService auditService;
    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final AtomicBoolean inFlight = new AtomicBoolean(false);
    private volatile Instant startedAt;
    private volatile Instant lastCompletedAt;
    private volatile String lastError;
    private volatile boolean reconstructed = false;

    public InitialSyncService(
            @Qualifier("initialSyncTaskExecutor") ThreadPoolTaskExecutor executor,
            NvdSyncService nvdSyncService,
            EpssIngestionService epssIngestionService,
            KevIngestionService kevIngestionService,
            AuditService auditService,
            AuditLogRepository auditLogRepository) {
        this.executor = executor;
        this.nvdSyncService = nvdSyncService;
        this.epssIngestionService = epssIngestionService;
        this.kevIngestionService = kevIngestionService;
        this.auditService = auditService;
        this.auditLogRepository = auditLogRepository;
    }

    /** Returns {@code true} if a sync job is currently executing. */
    public boolean isInFlight() {
        return inFlight.get();
    }

    /** Returns the {@link Instant} at which the current (or most recent) sync was started, or {@code null} if never triggered. */
    public Instant getStartedAt() {
        return startedAt;
    }

    /**
     * Returns the timestamp of the last completed sync. If in-memory state is absent
     * (e.g. after a restart), lazily reconstructs from the audit log.
     */
    public Instant getLastCompletedAt() {
        ensureReconstructed();
        return lastCompletedAt;
    }

    /**
     * Returns the last error message, or {@code null} on success. If in-memory state
     * is absent (e.g. after a restart), lazily reconstructs from the audit log.
     */
    public String getLastError() {
        ensureReconstructed();
        return lastError;
    }

    /**
     * Triggers the initial sync if none is currently running.
     *
     * <p>Returns immediately with a {@link InitialSyncResponse} indicating whether
     * a new sync was started or one was already in flight.
     */
    public InitialSyncResponse trigger(InitialSyncRequest req, String actor) {
        if (inFlight.compareAndSet(false, true)) {
            startedAt = Instant.now();
            executor.submit(() -> runSync(req, actor));
            return new InitialSyncResponse("started", startedAt);
        } else {
            return new InitialSyncResponse("already-running", startedAt);
        }
    }

    private void runSync(InitialSyncRequest req, String actor) {
        List<String> failedFeeds = new ArrayList<>();
        List<String> failureMessages = new ArrayList<>();

        try {
            String nvdErr = runNvd(req);
            if (nvdErr != null) {
                failedFeeds.add("NVD");
                failureMessages.add(nvdErr);
            }

            String epssErr = runEpss();
            if (epssErr != null) {
                failedFeeds.add("EPSS");
                failureMessages.add(epssErr);
            }

            String kevErr = runKev();
            if (kevErr != null) {
                failedFeeds.add("KEV");
                failureMessages.add(kevErr);
            }
        } finally {
            inFlight.set(false);
            boolean ok = failedFeeds.isEmpty();
            String errMsg = ok ? null : String.join("; ", failureMessages);

            // Update in-memory state
            lastCompletedAt = Instant.now();
            lastError = errMsg;
            reconstructed = true;

            // Persist terminal event to audit log
            Map<String, Object> payload = new HashMap<>();
            payload.put("completedAt", lastCompletedAt.toString());
            payload.put("ok", ok);
            payload.put("failedFeeds", failedFeeds);
            payload.put("lastError", errMsg);

            auditService.recordEvent(actor, "INITIAL_SYNC_COMPLETED", "initial-sync", "global", payload);
        }
    }

    /** Runs NVD bulk pull, returning the failure message or null on success. */
    private String runNvd(InitialSyncRequest req) {
        try {
            nvdSyncService.bulkPull(req.effectiveSince(), req.effectiveUntil());
            return null;
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.warn("Initial sync: NVD bulk pull failed — EPSS+KEV will still run: {}", e.getMessage(), e);
            return e.getMessage();
        }
    }

    /** Runs EPSS ingest, returning the failure message or null on success. */
    private String runEpss() {
        try {
            epssIngestionService.ingest();
            return null;
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.warn("Initial sync: EPSS ingest failed — KEV will still run: {}", e.getMessage(), e);
            return e.getMessage();
        }
    }

    /** Runs KEV ingest, returning the failure message or null on success. */
    private String runKev() {
        try {
            kevIngestionService.ingest();
            return null;
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.warn("Initial sync: KEV ingest failed: {}", e.getMessage(), e);
            return e.getMessage();
        }
    }

    /**
     * Lazily reconstructs {@code lastCompletedAt} and {@code lastError} from the
     * audit log when in-memory state is absent (after a restart).
     *
     * <p>R3: if no COMPLETED row exists but a TRIGGERED row does, reports "interrupted".
     */
    private synchronized void ensureReconstructed() {
        if (reconstructed) return;
        reconstructed = true;

        // Query for the latest INITIAL_SYNC_COMPLETED row
        var completedSpec = AuditQuerySpecifications.build(
                new AuditFilter(null, null, "INITIAL_SYNC_COMPLETED", null, null));
        Page<AuditLog> completedPage = auditLogRepository.findAll(
                completedSpec, PageRequest.of(0, 1, Sort.by(Sort.Direction.DESC, "occurredAt")));

        if (!completedPage.isEmpty()) {
            AuditLog row = completedPage.getContent().get(0);
            lastCompletedAt = row.getOccurredAt();
            lastError = parseLastError(row.getPayload());
            return;
        }

        // No COMPLETED row — check for TRIGGERED (R3: interrupted detection)
        var triggeredSpec = AuditQuerySpecifications.build(
                new AuditFilter(null, null, "INITIAL_SYNC_TRIGGERED", null, null));
        Page<AuditLog> triggeredPage = auditLogRepository.findAll(
                triggeredSpec, PageRequest.of(0, 1, Sort.by(Sort.Direction.DESC, "occurredAt")));

        if (!triggeredPage.isEmpty()) {
            // Sync was triggered but never completed — interrupted
            lastCompletedAt = null;
            lastError = "interrupted";
        }
        // else: never synced — both fields remain null
    }

    /**
     * Parses the {@code lastError} field from a JSON audit payload string.
     * Tolerates null/unparseable payloads.
     */
    private String parseLastError(String payloadJson) {
        if (payloadJson == null || payloadJson.isBlank()) return null;
        try {
            JsonNode node = objectMapper.readTree(payloadJson);
            if (node.has("ok") && node.get("ok").asBoolean(false)) {
                return null;
            }
            JsonNode errNode = node.get("lastError");
            if (errNode == null || errNode.isNull()) return null;
            return errNode.asText();
        } catch (Exception e) {
            log.warn("Failed to parse audit payload for sync status reconstruction: {}", e.getMessage());
            return "unknown";
        }
    }
}
