package io.castellum.discovery;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;

/**
 * Persists {@link DiscoverySweep} rows for each passive-discovery sweep. Replaces the
 * inline {@code clock.millis()} sweep-id placeholder previously used in
 * {@link PassiveDiscoveryService} with a real DB-backed FK back to {@code audit_log(id)}.
 *
 * <p>Two-phase contract: {@link #start} inserts a {@code RUNNING} row and returns the
 * generated id; {@link #finish} updates the same row with terminal status and counts.
 * Each method is its own transaction so the sweep row is visible to other readers
 * (e.g. the {@code GET /api/discovery/sweeps} listing) immediately after each phase.
 */
@Service
public class DiscoverySweepRecorder {

    private final DiscoverySweepRepository repo;
    private final Clock clock;

    public DiscoverySweepRecorder(DiscoverySweepRepository repo, Clock clock) {
        this.repo = repo;
        this.clock = clock;
    }

    @Transactional
    public Long start(String source, String iface, String triggeredBy) {
        DiscoverySweep s = new DiscoverySweep();
        s.setStartedAt(clock.instant());
        s.setSource(source);
        s.setIface(iface);
        s.setTriggeredBy(triggeredBy);
        s.setStatus("RUNNING");
        // neighborCount + deviceCount default 0 — set explicitly to avoid any ambiguity
        s.setNeighborCount(0);
        s.setDeviceCount(0);
        return repo.save(s).getId();
    }

    @Transactional
    public void finish(Long sweepId, String status, int neighborCount, int deviceCount, Long auditLogId) {
        DiscoverySweep s = repo.findById(sweepId)
            .orElseThrow(() -> new IllegalStateException(
                "DiscoverySweep id " + sweepId + " missing — recorder.start was not called"));
        s.setFinishedAt(clock.instant());
        s.setStatus(status);
        s.setNeighborCount(neighborCount);
        s.setDeviceCount(deviceCount);
        s.setAuditLogId(auditLogId);
        repo.save(s);
    }
}
