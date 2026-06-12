package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.discovery.DockerImageCpe;
import io.castellum.discovery.Discovery;
import io.castellum.discovery.DiscoverySource;
import io.castellum.discovery.DeviceUpsertService;
import io.castellum.discovery.probe.DockerHostProbeService;
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
 * <p>{@link #executeAsync(Long)} ({@link Async @Async("scanTaskExecutor")}) and
 * {@link #executeWideAsync(Long)} ({@code @Async("wideScanTaskExecutor")}) share one
 * execution body and are invoked from {@link io.castellum.web.ScanController} (and the
 * retry/recovery/scheduler dispatch sites) after the PENDING row has been persisted and
 * the {@code SCAN_SUBMIT} audit event emitted. Dispatch sites route via
 * {@link #isWideScan(String)}: multi-chunk scans go to the dedicated wide lane so a
 * multi-hour /16 sweep never starves the interactive pool.
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
    private final DockerHostProbeService dockerHostProbeService;

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
            AliveHostResolver aliveHostResolver,
            DockerHostProbeService dockerHostProbeService) {
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
        this.dockerHostProbeService = dockerHostProbeService;
    }

    /** Prefix length of each execution chunk. /22 = 1024 hosts per nmap run. */
    static final int CHUNK_PREFIX = 22;

    /**
     * True when {@code cidr} is wider than the chunk prefix and will execute as more
     * than one /22 chunk. Single source of truth for dispatch-site routing between
     * {@link #executeAsync} (interactive lane) and {@link #executeWideAsync} (wide lane).
     */
    public static boolean isWideScan(String cidr) {
        return CidrChunker.chunkInto(cidr, CHUNK_PREFIX).size() > 1;
    }

    /**
     * Execute an nmap scan asynchronously on the interactive {@code scanTaskExecutor}
     * pool. Dispatch sites route single-chunk scans (/22 or narrower) here and
     * multi-chunk scans to {@link #executeWideAsync} via {@link #isWideScan}.
     *
     * @param scanId the id of the persisted PENDING scan row
     */
    @Async("scanTaskExecutor")
    public void executeAsync(Long scanId) {
        execute(scanId);
    }

    /**
     * Execute a wide (multi-chunk) nmap scan asynchronously on the dedicated
     * single-threaded {@code wideScanTaskExecutor} lane. A /16 runs 64 sequential /22
     * chunks and can occupy a thread for hours — isolating it here keeps the
     * interactive pool free for single-chunk scans, retries, recovery, and the
     * scheduler.
     *
     * @param scanId the id of the persisted PENDING scan row
     */
    @Async("wideScanTaskExecutor")
    public void executeWideAsync(Long scanId) {
        execute(scanId);
    }

    /**
     * Shared execution body for both async lanes.
     *
     * <p>Loads the {@link Scan} entity fresh from the database, then drives it through the
     * {@code PENDING → RUNNING → COMPLETE | FAILED} lifecycle on the calling executor thread.
     *
     * <p>Every scan executes as a sequence of /22 chunks ({@link CidrChunker#chunkInto}):
     * a /22-or-narrower CIDR is a single chunk (identical to the pre-chunking flow), wider
     * ranges run one bounded nmap invocation per chunk, in ascending network order, with
     * {@code chunksDone} persisted after each. A chunk failure fails the whole scan
     * (fail-fast — remaining chunks are not attempted) with the failing chunk's CIDR
     * recorded in {@code failureReason}.
     *
     * <p>Resume: when the row already carries {@code chunksTotal} equal to the freshly
     * computed chunk count and {@code chunksDone} in {@code [1, count)} — i.e. a retry or
     * recovery of a partially completed wide scan — execution resumes at index
     * {@code chunksDone} instead of re-scanning completed chunks. Chunk order is
     * deterministic ascending, so index resume is sound. Fresh scans have null
     * {@code chunksDone} and start at 0.
     */
    private void execute(Long scanId) {
        // 1. Load — if absent, audit and bail.
        Optional<Scan> optional = scanRepository.findById(scanId);
        if (optional.isEmpty()) {
            log.warn("execute: scan {} not found — aborting", scanId);
            auditService.recordEvent("system", "SCAN_FAILED", "scan",
                String.valueOf(scanId), "scan row gone");
            return;
        }

        Scan scan = optional.get();

        List<String> chunks = null;
        String currentChunk = null;
        try {
            chunks = CidrChunker.chunkInto(scan.getCidr(), CHUNK_PREFIX);

            // Resume support: a retry/recovery of a partially completed wide scan keeps
            // its chunk progress — start at index chunksDone instead of re-scanning
            // completed chunks. Fresh scans (null chunksDone) start at 0, as does any
            // row whose persisted chunksTotal no longer matches the computed count.
            int startIndex = 0;
            if (scan.getChunksTotal() != null && scan.getChunksTotal() == chunks.size()
                    && scan.getChunksDone() != null
                    && scan.getChunksDone() >= 1 && scan.getChunksDone() < chunks.size()) {
                startIndex = scan.getChunksDone();
                log.info("execute: scan {} resuming at chunk {} of {}",
                    scanId, startIndex, chunks.size());
            }

            // 2. RUNNING — seed chunk progress in the same save (resumed scans keep
            // their completed-chunk count; it is never reset to 0).
            scan.setStatus(ScanStatus.RUNNING);
            scan.setChunksTotal(chunks.size());
            scan.setChunksDone(startIndex);
            scanRepository.save(scan);

            // 3. SCAN_EXECUTE audit — exactly once per scan, never per chunk.
            auditService.recordEvent("system", "SCAN_EXECUTE", "scan",
                String.valueOf(scanId), scan);

            ScanType type = ScanType.valueOf(scan.getScanType());

            // 3.5. Alive-host resolution — exactly once per scan, against the FULL CIDR.
            // Each resolver call performs a full device-inventory fetch; resolving per
            // chunk would repeat that fetch once per chunk (64x for a /16). Chunks
            // filter this list in memory via CidrValidator.cidrContainsHost.
            List<String> aliveHosts = null;
            if (type == ScanType.SERVICE_DETECT && !scan.isSkipHostDiscovery()) {
                aliveHosts = aliveHostResolver.aliveHostsIn(scan.getCidr());
                if (aliveHosts.isEmpty()) {
                    // No known-up hosts anywhere in the range. Do NOT fall back to
                    // scanning the whole range, and do NOT run the docker probe or
                    // self-check tail (legacy completeWithNoResults semantics — an
                    // empty inventory must not raise self-check findings).
                    log.info("execute: scan {} SERVICE_DETECT found no alive hosts in {} — "
                        + "completing with zero services", scanId, scan.getCidr());
                    completeWithNoResults(scan, scanId);
                    return;
                }
            }

            // 4-7. Run each chunk sequentially; persist progress after each.
            List<String> probeTargets = new ArrayList<>();
            for (int i = startIndex; i < chunks.size(); i++) {
                String chunk = chunks.get(i);
                currentChunk = chunk;
                executeChunk(scan, scanId, type, chunk, aliveHosts, probeTargets);
                scan.setChunksDone(scan.getChunksDone() + 1);
                scanRepository.save(scan);
            }
            currentChunk = null;

            // 7.5. Docker Host Probe — runs after discovery, before COMPLETE so that
            // riskCacheEvictor.onScanComplete() (step 10) invalidates risk for new findings.
            // Probe failures are isolated — a failure must NOT abort the scan.
            try {
                dockerHostProbeService.probeHosts(probeTargets);
            } catch (Exception probeEx) {
                log.warn("execute: docker host probe failed for scan {} — scan continues: {}",
                    scanId, probeEx.getMessage());
            }
            try {
                dockerHostProbeService.runSelfCheck();
            } catch (Exception selfCheckEx) {
                log.warn("execute: docker self-check failed for scan {} — scan continues: {}",
                    scanId, selfCheckEx.getMessage());
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
            // Multi-chunk scans name the failing chunk so the operator knows where the
            // sweep stopped; single-chunk scans keep the exact pre-chunking format.
            if (currentChunk != null && chunks != null && chunks.size() > 1) {
                failureReason = failureReason + " (chunk " + currentChunk + ")";
            }
            log.warn("execute: scan {} failed — {}", scanId, failureReason);

            try {
                scan.setStatus(ScanStatus.FAILED);
                scan.setFailureReason(failureReason);
                scan.setCompletedAt(Instant.now());
                scanRepository.save(scan);
            } catch (Exception saveEx) {
                log.error("execute: could not persist FAILED status for scan {}: {}", scanId, saveEx.getMessage());
            }

            auditService.recordEvent("system", "SCAN_FAILED", "scan",
                String.valueOf(scanId), failureReason);

            // F8: auto-retry hook — schedules a retry if the failure reason looks like
            // an nmap timeout and the per-scan retry budget remains. Audit-only call;
            // the ScanRetryService poller does the actual re-dispatch.
            try {
                scanRetryService.scheduleRetryIfApplicable(scan);
            } catch (Exception retryEx) {
                log.warn("execute: retry scheduling failed for scan {}: {}",
                    scanId, retryEx.getMessage());
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Run one /22 chunk through the single-scan flow: nmap → parse → upsert devices →
     * persist services. Emits NO audit events — audit cadence is per scan, not per chunk.
     *
     * <p>SERVICE_DETECT is scoped to the alive-host set within the chunk rather than the
     * whole range. PING_SWEEP (which the unified flow runs first) upserts every live
     * host into the device inventory; the caller resolves that inventory ONCE for the
     * whole scan CIDR and hands it in as {@code aliveHosts}; this method filters it to
     * the chunk in memory via {@link CidrValidator#cidrContainsHost}. Scoping to
     * known-up hosts lets the runner drop -Pn (no phantom inflation) and version-scan
     * only real hosts. An empty per-chunk alive set is a clean zero-result chunk —
     * never a whole-range fallback (the original timeout bug).
     *
     * <p>{@code skipHostDiscovery=true} bypasses the alive-host inventory for
     * SERVICE_DETECT: the whole chunk CIDR goes to the string-overload runner (whose
     * argv carries {@code -Pn} for port-enumerating types), and the zero-service
     * phantom-suppression branch stays active so -Pn ghosts are not upserted.
     * PING_SWEEP and OS_FINGERPRINT ignore the flag entirely.
     *
     * @param aliveHosts   once-per-scan alive set for the FULL scan CIDR; non-null and
     *                     non-empty exactly when {@code type == SERVICE_DETECT} and
     *                     {@code skipHostDiscovery} is false
     * @param probeTargets accumulator for discovered IPs — the docker host probe runs
     *                     once per scan, after all chunks
     */
    private void executeChunk(Scan scan, Long scanId, ScanType type, String chunkCidr,
                              List<String> aliveHosts, List<String> probeTargets)
            throws IOException, InterruptedException {
        boolean aliveHostPath = false;
        NmapResult result;
        if (type == ScanType.SERVICE_DETECT && !scan.isSkipHostDiscovery()) {
            List<String> chunkAliveHosts = new ArrayList<>();
            for (String host : aliveHosts) {
                if (CidrValidator.cidrContainsHost(chunkCidr, host)) {
                    chunkAliveHosts.add(host);
                }
            }
            if (chunkAliveHosts.isEmpty()) {
                log.info("execute: scan {} SERVICE_DETECT found no alive hosts in {} — "
                    + "zero services for this chunk", scanId, chunkCidr);
                return;
            }
            aliveHostPath = true;
            result = nmapRunner.run(chunkAliveHosts, type);
        } else {
            result = nmapRunner.run(chunkCidr, type);
        }

        // Parse output
        NmapOutputParser.ParsedScan parsed = nmapOutputParser.parse(result.stdout(), type);

        // Persist discovered hosts → devices
        Instant now = Instant.now();
        for (NmapOutputParser.DiscoveredHost host : parsed.hosts()) {
            // Collect this host's open services up-front.
            List<NmapOutputParser.DiscoveredService> hostServices = new ArrayList<>();
            for (NmapOutputParser.DiscoveredService svc : parsed.services()) {
                if (svc.ipAddress().equals(host.ipAddress())) {
                    hostServices.add(svc);
                }
            }

            // Phantom suppression: on the whole-CIDR path (skipHostDiscovery, or legacy
            // fallback), SERVICE_DETECT runs nmap with -Pn, which marks every address in the
            // CIDR "up" regardless of whether anything is listening. A host with zero open
            // services under -Pn is a phantom (e.g. the network/broadcast address) — skip it
            // entirely. The alive-host path drops -Pn and targets only hosts a prior
            // PING_SWEEP confirmed up, so there are no phantoms there: a known-up host with
            // no open ports is still a real device and must NOT be suppressed. PING_SWEEP
            // and OS_FINGERPRINT are unaffected.
            if (type == ScanType.SERVICE_DETECT && !aliveHostPath && hostServices.isEmpty()) {
                continue;
            }

            Discovery discovery = new Discovery(
                host.ipAddress(),
                null,           // MAC not available from nmap XML output
                host.hostname(),
                DiscoverySource.NMAP_SCAN,
                now,
                null,           // iface not available from nmap XML output
                false
            );
            Device device = deviceUpsertService.upsert(discovery, scanId);
            probeTargets.add(host.ipAddress());

            if (type == ScanType.OS_FINGERPRINT && host.os() != null) {
                device.setOsName(host.os().name());
                device.setOsAccuracy(host.os().accuracy());
                device.setOsCpe(host.os().cpe());
                deviceRepository.save(device);
            }

            // Persist discovered services linked to the device
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
    }

    /**
     * Mark a scan COMPLETE with no discovered services and emit the SCAN_COMPLETE audit +
     * risk-cache eviction, mirroring the tail of the happy path. Used by the SERVICE_DETECT
     * empty-alive-set short-circuit so an empty live set is a clean success, not a failure or
     * a whole-range fallback. Deliberately does NOT run the docker host probe or self-check:
     * the legacy pre-chunking path never did, and an empty inventory must not raise
     * self-check findings. chunksTotal/chunksDone keep the values the RUNNING seed wrote.
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
    /**
     * Returns {@code true} when a CPE 2.3 string has a wildcard ({@code *}) or empty version
     * component — meaning it matches all versions and would over-report CVEs.
     *
     * <p>CPE 2.3 format: {@code cpe:2.3:type:vendor:product:version:...}
     * Version is the 5th colon-separated component (index 4).
     */
    private static boolean nmapCpeIsVersionless(String cpe) {
        if (cpe == null) {
            return true;
        }
        // CPE 2.3: cpe:2.3:a:vendor:product:version:...
        String[] parts = cpe.split(":", -1);
        if (parts.length < 6) {
            return true; // malformed — treat as versionless to be safe
        }
        String version = parts[5];
        return version.isEmpty() || "*".equals(version);
    }

    private static void applyNmapFingerprint(NetworkService ns,
                                              NmapOutputParser.DiscoveredService svc) {
        String product = svc.product();
        if (product != null && !product.isBlank()) {
            // nmap identified the software: use the fingerprint as the authoritative source
            ns.setName(product);   // human-readable display (e.g. "MySQL")
            ns.setProduct(product.toLowerCase(java.util.Locale.ROOT));
            ns.setVersion(svc.version());
            // Prefer nmap-supplied CPE only when it carries a concrete version; otherwise a
            // version-less nmap CPE (version field = "*" or empty) would match every CVE filed
            // against the product. If nmap's CPE is version-less AND we can derive a versioned
            // CPE from the curated product map, use the derived one instead.
            String derivedCpe = DockerImageCpe.cpeForFingerprint(product, svc.version());
            String cpe;
            if (svc.cpe23() != null && !nmapCpeIsVersionless(svc.cpe23()) ) {
                cpe = svc.cpe23();
            } else if (derivedCpe != null) {
                cpe = derivedCpe;
            } else {
                cpe = svc.cpe23(); // may be null or a version-less CPE — best we have
            }
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
