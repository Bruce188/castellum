package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.discovery.DockerImageCpe;
import io.castellum.discovery.Discovery;
import io.castellum.discovery.DiscoverySource;
import io.castellum.discovery.DeviceUpsertService;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import io.castellum.risk.RiskCacheEvictor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
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
    private final RiskCacheEvictor riskCacheEvictor;
    private final DeviceRepository deviceRepository;
    private final AliveHostResolver aliveHostResolver;

    public ScanExecutionService(
            NmapRunner nmapRunner,
            ScanRepository scanRepository,
            NmapOutputParser nmapOutputParser,
            DeviceUpsertService deviceUpsertService,
            NetworkServiceRepository networkServiceRepository,
            AuditService auditService,
            ScanRetryService scanRetryService,
            RiskCacheEvictor riskCacheEvictor,
            DeviceRepository deviceRepository,
            AliveHostResolver aliveHostResolver) {
        this.nmapRunner = nmapRunner;
        this.scanRepository = scanRepository;
        this.nmapOutputParser = nmapOutputParser;
        this.deviceUpsertService = deviceUpsertService;
        this.networkServiceRepository = networkServiceRepository;
        this.auditService = auditService;
        this.scanRetryService = scanRetryService;
        this.riskCacheEvictor = riskCacheEvictor;
        this.deviceRepository = deviceRepository;
        this.aliveHostResolver = aliveHostResolver;
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

            // 4. Run nmap.
            //
            // SERVICE_DETECT is scoped to the alive-host set within the CIDR rather than the
            // whole range. PING_SWEEP (which the unified flow runs first) upserts every live
            // host into the device inventory; AliveHostResolver reads that inventory filtered
            // to the CIDR. Scoping to known-up hosts lets the runner drop -Pn (no phantom
            // inflation) and version-scan only real hosts, so a /22 no longer multiplies -sV
            // across 1024 forced-up addresses.
            ScanType type = ScanType.valueOf(scan.getScanType());

            boolean aliveHostPath = false;
            NmapResult result;
            if (type == ScanType.SERVICE_DETECT) {
                List<String> aliveHosts = aliveHostResolver.aliveHostsIn(scan.getCidr());
                if (aliveHosts.isEmpty()) {
                    // No known-up hosts in this CIDR. Do NOT fall back to scanning the whole
                    // range (that is the original timeout bug). Complete with zero services.
                    log.info("executeAsync: scan {} SERVICE_DETECT found no alive hosts in {} — "
                        + "completing with zero services", scanId, scan.getCidr());
                    completeWithNoResults(scan, scanId);
                    return;
                }
                aliveHostPath = true;
                result = nmapRunner.run(aliveHosts, type);
            } else {
                result = nmapRunner.run(scan.getCidr(), type);
            }

            // 5. Parse output
            NmapOutputParser.ParsedScan parsed = nmapOutputParser.parse(result.stdout(), type);

            // 6. Persist discovered hosts → devices
            Instant now = Instant.now();
            for (NmapOutputParser.DiscoveredHost host : parsed.hosts()) {
                // Collect this host's open services up-front.
                List<NmapOutputParser.DiscoveredService> hostServices = new ArrayList<>();
                for (NmapOutputParser.DiscoveredService svc : parsed.services()) {
                    if (svc.ipAddress().equals(host.ipAddress())) {
                        hostServices.add(svc);
                    }
                }

                // Phantom suppression: on the whole-CIDR fallback, SERVICE_DETECT runs nmap with
                // -Pn, which marks every address in the CIDR "up" regardless of whether anything
                // is listening. A host with zero open services under -Pn is a phantom (e.g. the
                // network/broadcast address) — skip it entirely. The alive-host path drops -Pn
                // and targets only hosts a prior PING_SWEEP confirmed up, so there are no
                // phantoms there: a known-up host with no open ports is still a real device and
                // must NOT be suppressed. PING_SWEEP and OS_FINGERPRINT are unaffected.
                if (type == ScanType.SERVICE_DETECT && !aliveHostPath && hostServices.isEmpty()) {
                    continue;
                }

                Discovery discovery = new Discovery(
                    host.ipAddress(),
                    null,           // MAC not available from nmap XML output
                    host.hostname(),
                    DiscoverySource.NMAP_SCAN,
                    now,
                    null            // iface not available from nmap XML output
                );
                Device device = deviceUpsertService.upsert(discovery);

                if (type == ScanType.OS_FINGERPRINT && host.os() != null) {
                    device.setOsName(host.os().name());
                    device.setOsAccuracy(host.os().accuracy());
                    device.setOsCpe(host.os().cpe());
                    deviceRepository.save(device);
                }

                // 7. Persist discovered services linked to the device
                for (NmapOutputParser.DiscoveredService svc : hostServices) {
                    Optional<NetworkService> existing =
                        networkServiceRepository.findByDeviceIdAndPortAndProtocol(
                            device.getId(), svc.port(), svc.protocol());
                    NetworkService ns = existing.orElseGet(NetworkService::new);
                    if (existing.isEmpty()) {
                        ns.setDeviceId(device.getId());
                        ns.setPort(svc.port());
                        ns.setProtocol(svc.protocol());
                    }
                    applyNmapFingerprint(ns, svc);
                    ns.setObservedAt(now);
                    networkServiceRepository.save(ns);
                }
            }

            // 8. COMPLETE
            scan.setStatus(ScanStatus.COMPLETE);
            scan.setCompletedAt(Instant.now());
            scanRepository.save(scan);

            // 9. SCAN_COMPLETE audit
            auditService.recordEvent("system", "SCAN_COMPLETE", "scan",
                String.valueOf(scanId), scan);

            // 10. Invalidate risk/CVE aggregate caches — newly discovered services/CVEs can
            // change per-device scores, the top-N ranking, and the fleet CVE listing.
            riskCacheEvictor.onScanComplete();

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

    /**
     * Mark a scan COMPLETE with no discovered services and emit the SCAN_COMPLETE audit +
     * risk-cache eviction, mirroring the tail of the happy path. Used by the SERVICE_DETECT
     * empty-alive-set short-circuit so an empty live set is a clean success, not a failure or
     * a whole-range fallback.
     */
    private void completeWithNoResults(Scan scan, Long scanId) {
        scan.setStatus(ScanStatus.COMPLETE);
        scan.setCompletedAt(Instant.now());
        scanRepository.save(scan);
        auditService.recordEvent("system", "SCAN_COMPLETE", "scan",
            String.valueOf(scanId), scan);
        riskCacheEvictor.onScanComplete();
    }

    private static String buildFailureReason(Exception e) {
        String className = e.getClass().getSimpleName();
        String message = e.getMessage() != null ? e.getMessage() : "";
        String combined = className + ": " + message;
        return combined.length() > FAILURE_REASON_MAX_LEN
            ? combined.substring(0, FAILURE_REASON_MAX_LEN)
            : combined;
    }

    /**
     * Apply nmap SERVICE_DETECT fingerprint data to a {@link NetworkService} row.
     *
     * <p>When nmap reports a non-null {@code product} (e.g. "MySQL"), that product is
     * authoritative and supersedes whatever a prior docker-discovery pass may have written:
     * <ul>
     *   <li>{@code name} ← the nmap product string (human-readable display name)</li>
     *   <li>{@code product} ← product lowercased (matches {@link DockerImageCpe#PRODUCTS} keys)</li>
     *   <li>{@code version} ← nmap version verbatim (e.g. "8.0.46-1.el9")</li>
     *   <li>{@code cpe} ← nmap-provided CPE 2.3 string if present; otherwise derived via
     *       {@link DockerImageCpe#cpeForFingerprint} when the product is in the curated map</li>
     * </ul>
     *
     * <p>When nmap has no product, the standard port-scan fields (protocol name, version) are
     * written without touching an existing CPE — so a docker-derived CPE is not cleared by a
     * no-product nmap result.
     *
     * <p>Either way the caller must still set {@code observedAt} and save.
     */
    private static void applyNmapFingerprint(NetworkService ns,
                                              NmapOutputParser.DiscoveredService svc) {
        String product = svc.product();
        if (product != null && !product.isBlank()) {
            // nmap identified the software: use the fingerprint as the authoritative source
            ns.setName(product);   // human-readable display (e.g. "MySQL")
            ns.setProduct(product.toLowerCase(java.util.Locale.ROOT));
            ns.setVersion(svc.version());
            // Prefer nmap-supplied CPE; fall back to derived CPE from the curated product map
            String cpe = svc.cpe23() != null
                ? svc.cpe23()
                : DockerImageCpe.cpeForFingerprint(product, svc.version());
            ns.setCpe(cpe);
        } else {
            // No product fingerprint — record protocol name + version but do not clear an
            // existing CPE (which may have been derived from the docker image tag)
            ns.setName(svc.name());
            ns.setVersion(svc.version());
            ns.setProduct(null);
            // Preserve existing CPE; only set from nmap if it actually provided one
            if (svc.cpe23() != null) {
                ns.setCpe(svc.cpe23());
            }
        }
    }
}
