package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.discovery.Discovery;
import io.castellum.discovery.DiscoverySource;
import io.castellum.discovery.DeviceUpsertService;
import io.castellum.domain.Device;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

/**
 * Asynchronous scan execution service.
 *
 * <p>{@link #executeAsync(Long)} is annotated {@link Async @Async("scanTaskExecutor")}
 * and is invoked from {@link io.castellum.web.ScanController} after the PENDING row
 * has been persisted and the {@code SCAN_SUBMIT} audit event emitted.
 *
 * <p>The method takes a {@code scanId} (not the entity) so the async thread loads a
 * fresh entity in its own persistence context — avoiding stale-detached-entity bugs.
 *
 * <p>Status transitions: {@code PENDING → RUNNING → COMPLETE | FAILED}.
 * Each terminal transition emits a matching audit event:
 * {@code SCAN_EXECUTE} (before runner), {@code SCAN_COMPLETE} or {@code SCAN_FAILED} (after).
 *
 * <p>Exception handling: a single {@code catch (Exception e)} covers {@link IOException},
 * {@link InterruptedException}, and any {@link RuntimeException} thrown by the runner or
 * parser. For {@link InterruptedException}, the interrupt flag is restored via
 * {@link Thread#interrupt()} before returning.
 */
@Service
public class ScanExecutionService {

    private static final Logger log = LoggerFactory.getLogger(ScanExecutionService.class);

    /** Maximum characters kept from the exception message in the failure_reason column. */
    private static final int FAILURE_REASON_MAX_LEN = 500;

    private final NmapRunner nmapRunner;
    private final ScanRepository scanRepository;
    private final NmapOutputParser nmapOutputParser;
    private final DeviceUpsertService deviceUpsertService;
    private final NetworkServiceRepository networkServiceRepository;
    private final AuditService auditService;
    private final ScanRetryService scanRetryService;

    public ScanExecutionService(
            NmapRunner nmapRunner,
            ScanRepository scanRepository,
            NmapOutputParser nmapOutputParser,
            DeviceUpsertService deviceUpsertService,
            NetworkServiceRepository networkServiceRepository,
            AuditService auditService,
            ScanRetryService scanRetryService) {
        this.nmapRunner = nmapRunner;
        this.scanRepository = scanRepository;
        this.nmapOutputParser = nmapOutputParser;
        this.deviceUpsertService = deviceUpsertService;
        this.networkServiceRepository = networkServiceRepository;
        this.auditService = auditService;
        this.scanRetryService = scanRetryService;
    }

    /**
     * Execute an nmap scan asynchronously.
     *
     * <p>Loads the {@link Scan} entity fresh from the database, then drives it through the
     * {@code PENDING → RUNNING → COMPLETE | FAILED} lifecycle on the caller thread of the
     * {@code scanTaskExecutor} pool.
     *
     * @param scanId the id of the persisted PENDING scan row
     */
    @Async("scanTaskExecutor")
    public void executeAsync(Long scanId) {
        // 1. Load — if absent, audit and bail.
        Optional<Scan> optional = scanRepository.findById(scanId);
        if (optional.isEmpty()) {
            log.warn("executeAsync: scan {} not found — aborting", scanId);
            auditService.recordEvent("system", "SCAN_FAILED", "scan",
                String.valueOf(scanId), "scan row gone");
            return;
        }

        Scan scan = optional.get();

        try {
            // 2. RUNNING
            scan.setStatus(ScanStatus.RUNNING);
            scanRepository.save(scan);

            // 3. SCAN_EXECUTE audit
            auditService.recordEvent("system", "SCAN_EXECUTE", "scan",
                String.valueOf(scanId), scan);

            // 4. Run nmap
            ScanType type = ScanType.valueOf(scan.getScanType());
            NmapResult result = nmapRunner.run(scan.getCidr(), type);

            // 5. Parse output
            NmapOutputParser.ParsedScan parsed = nmapOutputParser.parse(result.stdout(), type);

            // 6. Persist discovered hosts → devices
            Instant now = Instant.now();
            for (NmapOutputParser.DiscoveredHost host : parsed.hosts()) {
                Discovery discovery = new Discovery(
                    host.ipAddress(),
                    null,           // MAC not available from nmap text output
                    host.hostname(),
                    DiscoverySource.NMAP_SCAN,
                    now,
                    null            // iface not available from nmap text output
                );
                Device device = deviceUpsertService.upsert(discovery);

                // 7. Persist discovered services linked to the device
                for (NmapOutputParser.DiscoveredService svc : parsed.services()) {
                    if (svc.ipAddress().equals(host.ipAddress())) {
                        Optional<NetworkService> existing =
                            networkServiceRepository.findByDeviceIdAndPortAndProtocol(
                                device.getId(), svc.port(), svc.protocol());
                        if (existing.isPresent()) {
                            NetworkService ns = existing.get();
                            ns.setName(svc.name());
                            ns.setVersion(svc.version());
                            ns.setObservedAt(now);
                            networkServiceRepository.save(ns);
                        } else {
                            NetworkService ns = new NetworkService();
                            ns.setDeviceId(device.getId());
                            ns.setPort(svc.port());
                            ns.setProtocol(svc.protocol());
                            ns.setName(svc.name());
                            ns.setVersion(svc.version());
                            ns.setObservedAt(now);
                            networkServiceRepository.save(ns);
                        }
                    }
                }
            }

            // 8. COMPLETE
            scan.setStatus(ScanStatus.COMPLETE);
            scan.setCompletedAt(Instant.now());
            scanRepository.save(scan);

            // 9. SCAN_COMPLETE audit
            auditService.recordEvent("system", "SCAN_COMPLETE", "scan",
                String.valueOf(scanId), scan);

        } catch (Exception e) {
            // Restore interrupt flag for InterruptedException
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }

            String failureReason = buildFailureReason(e);
            log.warn("executeAsync: scan {} failed — {}", scanId, failureReason);

            try {
                scan.setStatus(ScanStatus.FAILED);
                scan.setFailureReason(failureReason);
                scan.setCompletedAt(Instant.now());
                scanRepository.save(scan);
            } catch (Exception saveEx) {
                log.error("executeAsync: could not persist FAILED status for scan {}: {}", scanId, saveEx.getMessage());
            }

            auditService.recordEvent("system", "SCAN_FAILED", "scan",
                String.valueOf(scanId), failureReason);

            // F8: auto-retry hook — schedules a retry if the failure reason looks like
            // an nmap timeout and the per-scan retry budget remains. Audit-only call;
            // the ScanRetryService poller does the actual re-dispatch.
            try {
                scanRetryService.scheduleRetryIfApplicable(scan);
            } catch (Exception retryEx) {
                log.warn("executeAsync: retry scheduling failed for scan {}: {}",
                    scanId, retryEx.getMessage());
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static String buildFailureReason(Exception e) {
        String className = e.getClass().getSimpleName();
        String message = e.getMessage() != null ? e.getMessage() : "";
        String combined = className + ": " + message;
        return combined.length() > FAILURE_REASON_MAX_LEN
            ? combined.substring(0, FAILURE_REASON_MAX_LEN)
            : combined;
    }
}
