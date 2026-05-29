package io.castellum.discovery.probe;

import io.castellum.audit.AuditService;
import io.castellum.discovery.DockerContainer;
import io.castellum.discovery.DockerDiscoveryService;
import io.castellum.discovery.DockerInspectParser;
import io.castellum.discovery.DeviceUpsertService;
import io.castellum.discovery.OriginContext;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.Inet4Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Semaphore;
import java.util.function.Predicate;

/**
 * Orchestrates active, READ-ONLY Docker Host Probe across scan-discovered hosts.
 *
 * <p>For each target host IP:
 * <ol>
 *   <li>TCP-probe port {@code :2375} (plaintext). If reachable, pull containers via the
 *       {@link DockerEngineApiClient} (GET-only), map and {@link DockerDiscoveryService#ingest}
 *       them attributed to the probed host as origin, AND raise a CRITICAL posture finding.</li>
 *   <li>TCP-probe {@code :2376}/{@code :2377} (TLS/Swarm). If reachable, raise a HIGH posture
 *       finding only — no extraction (no cert handling).</li>
 *   <li>Closed port → fast no-op (no finding, no devices).</li>
 *   <li>Per-host failures are isolated — a malformed response or exception on one host must
 *       NOT abort the scan.</li>
 * </ol>
 *
 * <p>Self-check ({@link #runSelfCheck()}): enumerates local non-loopback IPv4 interfaces via
 * {@link NetworkInterface} and checks whether any is reachable on {@code :2375}. Raises a CRITICAL
 * self-finding if a non-loopback bind is detected.
 *
 * <p>Mirrors the {@link io.castellum.ot.OtFingerprintService} orchestration pattern:
 * {@link Semaphore} concurrency cap, per-probe timeouts, per-probe audit success +
 * REQUIRES_NEW failure audit.
 *
 * <p><b>READ-ONLY invariant:</b> all Docker Engine API calls are delegated to
 * {@link DockerEngineApiClient}, which exposes only GET methods. This class never issues
 * state-changing API calls.
 */
@Service
public class DockerHostProbeService {

    private static final Logger log = LoggerFactory.getLogger(DockerHostProbeService.class);

    /** Value stored in {@code service.protocol_family} for docker-exposure findings. */
    public static final String PROTOCOL_FAMILY_DOCKER_EXPOSURE = "DOCKER_EXPOSURE";

    /** Service name stored on a docker-engine-api-exposed finding row. */
    static final String FINDING_NAME = "docker-engine-api-exposed";

    /** Maximum containers accepted from a single host probe. Bounds R4 untrusted-input. */
    static final int MAX_CONTAINERS_PER_HOST = 5000;

    /** Probe ports and their posture severities. */
    static final int PORT_2375 = 2375;
    static final int PORT_2376 = 2376;
    static final int PORT_2377 = 2377;
    static final String SEVERITY_CRITICAL = "CRITICAL";
    static final String SEVERITY_HIGH = "HIGH";

    private final DeviceUpsertService deviceUpsertService;
    private final DeviceRepository deviceRepository;
    private final DockerDiscoveryService dockerDiscoveryService;
    private final DockerEngineApiClient apiClient;
    private final DockerApiNetworkMapper networkMapper;
    private final DockerApiContainerListMapper containerListMapper;
    private final DockerInspectParser inspectParser;
    private final NetworkServiceRepository networkServiceRepository;
    private final AuditService auditService;
    private final Semaphore concurrencyLimiter;
    private final Predicate<HostPort> reachable;

    @org.springframework.beans.factory.annotation.Autowired
    public DockerHostProbeService(
            DeviceUpsertService deviceUpsertService,
            DeviceRepository deviceRepository,
            DockerDiscoveryService dockerDiscoveryService,
            DockerEngineApiClient apiClient,
            DockerApiNetworkMapper networkMapper,
            DockerApiContainerListMapper containerListMapper,
            DockerInspectParser inspectParser,
            NetworkServiceRepository networkServiceRepository,
            AuditService auditService,
            @Value("${castellum.docker.probe.connect-timeout-ms:2000}") int connectTimeoutMs,
            @Value("${castellum.docker.probe.read-timeout-ms:5000}") int readTimeoutMs,
            @Value("${castellum.docker.probe.max-concurrent:8}") int maxConcurrent) {
        this(deviceUpsertService, deviceRepository, dockerDiscoveryService, apiClient,
             networkMapper, containerListMapper, inspectParser, networkServiceRepository,
             auditService, maxConcurrent,
             // Default reachability seam: real TCP connect
             hp -> {
                 try (Socket s = new Socket()) {
                     s.connect(new java.net.InetSocketAddress(hp.host(), hp.port()), connectTimeoutMs);
                     return true;
                 } catch (Exception e) {
                     return false;
                 }
             });
    }

    /** Test seam constructor — caller supplies reachability predicate. */
    public DockerHostProbeService(
            DeviceUpsertService deviceUpsertService,
            DeviceRepository deviceRepository,
            DockerDiscoveryService dockerDiscoveryService,
            DockerEngineApiClient apiClient,
            DockerApiNetworkMapper networkMapper,
            DockerApiContainerListMapper containerListMapper,
            DockerInspectParser inspectParser,
            NetworkServiceRepository networkServiceRepository,
            AuditService auditService,
            int maxConcurrent,
            Predicate<HostPort> reachable) {
        this.deviceUpsertService = deviceUpsertService;
        this.deviceRepository = deviceRepository;
        this.dockerDiscoveryService = dockerDiscoveryService;
        this.apiClient = apiClient;
        this.networkMapper = networkMapper;
        this.containerListMapper = containerListMapper;
        this.inspectParser = inspectParser;
        this.networkServiceRepository = networkServiceRepository;
        this.auditService = auditService;
        this.concurrencyLimiter = new Semaphore(maxConcurrent);
        this.reachable = reachable;
    }

    /**
     * Probe each target host IP for Docker daemon exposure.
     *
     * <p>Failures on individual hosts are isolated — one bad host does not abort the loop.
     *
     * @param targetHostIps list of host IP strings to probe (scan-authorized boundary)
     */
    public void probeHosts(List<String> targetHostIps) {
        for (String ip : targetHostIps) {
            try {
                concurrencyLimiter.acquire();
                try {
                    probeOne(ip);
                } finally {
                    concurrencyLimiter.release();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.warn("DockerHostProbeService: interrupted while probing hosts — aborting loop");
                return;
            } catch (Exception e) {
                log.warn("DockerHostProbeService: probe of {} failed — continuing with remaining hosts: {}",
                    ip, e.getMessage());
            }
        }
    }

    /**
     * Self-check: enumerate local non-loopback IPv4 interfaces and raise a CRITICAL finding
     * if any is reachable on port 2375 (docker daemon exposed on a non-loopback interface).
     */
    public void runSelfCheck() {
        List<String> nonLoopbackIps = localNonLoopbackIpv4();
        for (String ip : nonLoopbackIps) {
            try {
                if (reachable.test(new HostPort(ip, PORT_2375))) {
                    log.warn("DockerHostProbeService: self-check — docker daemon reachable on non-loopback {}", ip);
                    // Find or create the local host device
                    Optional<Device> selfDevice = deviceRepository.findByIpAddressAndOriginHostIp(ip, "local");
                    if (selfDevice.isPresent()) {
                        raiseExposureFinding(selfDevice.get().getId(), PORT_2375, SEVERITY_CRITICAL);
                    } else {
                        log.debug("DockerHostProbeService: self-check — no local device row for {}, skipping finding", ip);
                    }
                }
            } catch (Exception e) {
                log.warn("DockerHostProbeService: self-check failed for {}: {}", ip, e.getMessage());
            }
        }
    }

    // ---- Private implementation ----

    private void probeOne(String ip) {
        long startMs = System.currentTimeMillis();

        // Try :2375 first (plaintext)
        if (reachable.test(new HostPort(ip, PORT_2375))) {
            log.info("DockerHostProbeService: {} :2375 reachable — probing and ingesting", ip);
            probe2375(ip, startMs);
            return;
        }

        // :2376 (TLS) — finding only, no extraction
        if (reachable.test(new HostPort(ip, PORT_2376))) {
            log.info("DockerHostProbeService: {} :2376 reachable — raising HIGH finding (no extraction)", ip);
            probe2376or2377(ip, PORT_2376, startMs);
            return;
        }

        // :2377 (Swarm) — finding only, no extraction
        if (reachable.test(new HostPort(ip, PORT_2377))) {
            log.info("DockerHostProbeService: {} :2377 reachable — raising HIGH finding (no extraction)", ip);
            probe2376or2377(ip, PORT_2377, startMs);
            return;
        }

        // All ports closed — fast no-op
        log.debug("DockerHostProbeService: {} all probe ports closed — no-op", ip);
    }

    private void probe2375(String ip, long startMs) {
        try {
            // Pull container list
            Optional<String> containerListOpt = apiClient.getContainers(ip, PORT_2375);
            if (containerListOpt.isEmpty()) {
                log.debug("DockerHostProbeService: {} :2375 container list empty — raising finding only", ip);
                raiseFindingForExistingDevice(ip, PORT_2375, SEVERITY_CRITICAL);
                emitAuditSuccess(ip, PORT_2375, "reachable-no-data", startMs);
                return;
            }

            List<String> containerIds = containerListMapper.containerIds(containerListOpt.get());
            if (containerIds.size() > MAX_CONTAINERS_PER_HOST) {
                log.warn("DockerHostProbeService: {} container count {} exceeds cap {} — truncating",
                    ip, containerIds.size(), MAX_CONTAINERS_PER_HOST);
                containerIds = containerIds.subList(0, MAX_CONTAINERS_PER_HOST);
            }

            // Fetch and parse each container via inspect endpoint
            List<DockerContainer> containers = new ArrayList<>();
            for (String cid : containerIds) {
                Optional<String> inspectOpt = apiClient.getContainerInspect(ip, PORT_2375, cid);
                if (inspectOpt.isEmpty()) continue;
                try {
                    // DockerInspectParser.parse takes an array; wrap in brackets
                    String inspectJson = inspectOpt.get().trim();
                    if (!inspectJson.startsWith("[")) {
                        inspectJson = "[" + inspectJson + "]";
                    }
                    List<DockerContainer> parsed = inspectParser.parse(inspectJson);
                    containers.addAll(parsed);
                } catch (Exception e) {
                    log.warn("DockerHostProbeService: {} malformed inspect for container {} — skipping: {}",
                        ip, cid, e.getMessage());
                }
            }

            // Ingest containers attributed to the probed host
            OriginContext origin = OriginContext.of(ip, ip);
            Instant now = Instant.now();
            dockerDiscoveryService.ingest(containers, origin, now);

            // Raise CRITICAL posture finding for the probed host device
            raiseFindingForExistingDevice(ip, PORT_2375, SEVERITY_CRITICAL);

            emitAuditSuccess(ip, PORT_2375, "success containers=" + containers.size(), startMs);

        } catch (Exception e) {
            log.warn("DockerHostProbeService: {} :2375 probe failed: {}", ip, e.getMessage());
            emitAuditFailure(ip, PORT_2375, e, startMs);
        }
    }

    private void probe2376or2377(String ip, int port, long startMs) {
        try {
            raiseFindingForExistingDevice(ip, port, SEVERITY_HIGH);
            emitAuditSuccess(ip, port, "reachable-tls-no-extraction", startMs);
        } catch (Exception e) {
            log.warn("DockerHostProbeService: {} :{} finding upsert failed: {}", ip, port, e.getMessage());
            emitAuditFailure(ip, port, e, startMs);
        }
    }

    /**
     * Raise a posture finding for the host device identified by the given IP.
     * If the host device does not exist in the inventory (not yet scan-discovered), skip.
     */
    private void raiseFindingForExistingDevice(String ip, int port, String severity) {
        Optional<Device> deviceOpt = deviceRepository.findByIpAddressAndOriginHostIp(ip, "local");
        if (deviceOpt.isEmpty()) {
            log.debug("DockerHostProbeService: no inventory row for {} — skipping finding", ip);
            return;
        }
        raiseExposureFinding(deviceOpt.get().getId(), port, severity);
    }

    /**
     * Upsert a posture finding row on the given device's (port, "tcp") NetworkService.
     * Mirrors {@link io.castellum.ot.OtFingerprintService} L188-200.
     */
    private void raiseExposureFinding(Long deviceId, int port, String severity) {
        NetworkService svc = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(deviceId, port, "tcp")
            .orElseGet(NetworkService::new);
        svc.setDeviceId(deviceId);
        svc.setPort(port);
        svc.setProtocol("tcp");
        svc.setName(FINDING_NAME);
        svc.setProtocolFamily(PROTOCOL_FAMILY_DOCKER_EXPOSURE);
        svc.setPostureSeverity(severity);
        svc.setObservedAt(Instant.now());
        networkServiceRepository.save(svc);
    }

    private void emitAuditSuccess(String ip, int port, String detail, long startMs) {
        long durationMs = System.currentTimeMillis() - startMs;
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("host", ip);
        payload.put("port", port);
        payload.put("outcome", "success");
        payload.put("detail", detail);
        payload.put("durationMs", durationMs);
        auditService.recordEvent("system", "DOCKER_PROBE", "docker_probe",
            ip + ":" + port, payload);
    }

    private void emitAuditFailure(String ip, int port, Exception e, long startMs) {
        long durationMs = System.currentTimeMillis() - startMs;
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("host", ip);
        payload.put("port", port);
        payload.put("outcome", "failure");
        payload.put("errorClass", e.getClass().getSimpleName());
        String msg = e.getMessage();
        if (msg != null && msg.length() > 256) msg = msg.substring(0, 256);
        payload.put("errorMessage", msg);
        payload.put("durationMs", durationMs);
        auditService.recordEvent("system", "DOCKER_PROBE", "docker_probe",
            ip + ":" + port, payload);
    }

    /** Enumerate local non-loopback IPv4 interface addresses, mirroring PassiveDiscoveryController. */
    private static List<String> localNonLoopbackIpv4() {
        List<String> ips = new ArrayList<>();
        try {
            var nics = NetworkInterface.getNetworkInterfaces();
            if (nics == null) return ips;
            for (NetworkInterface nic : Collections.list(nics)) {
                try {
                    if (!nic.isUp() || nic.isLoopback()) continue;
                    for (InterfaceAddress ia : nic.getInterfaceAddresses()) {
                        if (ia.getAddress() instanceof Inet4Address) {
                            ips.add(ia.getAddress().getHostAddress());
                        }
                    }
                } catch (SocketException ignored) {
                    // Interface disappeared — skip
                }
            }
        } catch (SocketException e) {
            log.debug("DockerHostProbeService: could not enumerate network interfaces: {}", e.getMessage());
        }
        return ips;
    }
}
