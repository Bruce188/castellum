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

    /** Value stored in {@code service.protocol_family} for SNMP-exposure findings. */
    public static final String PROTOCOL_FAMILY_SNMP_EXPOSURE = "SNMP_EXPOSURE";

    /** Value stored in {@code service.protocol_family} for Traefik-exposure findings. */
    public static final String PROTOCOL_FAMILY_TRAEFIK_EXPOSURE = "TRAEFIK_EXPOSURE";

    /** Value stored in {@code service.protocol_family} for Portainer-exposure findings. */
    public static final String PROTOCOL_FAMILY_PORTAINER_EXPOSURE = "PORTAINER_EXPOSURE";

    /** Value stored in {@code service.protocol_family} for cAdvisor-exposure findings. */
    public static final String PROTOCOL_FAMILY_CADVISOR_EXPOSURE = "CADVISOR_EXPOSURE";

    /** Value stored in {@code service.protocol_family} for Kubernetes API exposure findings. */
    public static final String PROTOCOL_FAMILY_K8S_API_EXPOSURE = "K8S_API_EXPOSURE";

    /** Value stored in {@code service.protocol_family} for kubelet read-only port exposure findings. */
    public static final String PROTOCOL_FAMILY_KUBELET_RO_EXPOSURE = "KUBELET_RO_EXPOSURE";

    /** Value stored in {@code service.protocol_family} for Docker Registry exposure findings. */
    public static final String PROTOCOL_FAMILY_REGISTRY_EXPOSURE = "REGISTRY_EXPOSURE";

    /** Service name stored on a docker-engine-api-exposed finding row. */
    static final String FINDING_NAME = "docker-engine-api-exposed";

    /** Maximum containers accepted from a single host probe. Bounds R4 untrusted-input. */
    static final int MAX_CONTAINERS_PER_HOST = 5000;

    /**
     * Per-repository tag cap: at most this many tags are folded into the registry_images blob
     * for a single repository. Bounds blob-DoS from a crafted registry returning unlimited tags.
     */
    private static final int MAX_TAGS_PER_REPO = 64;

    /** Probe ports and their posture severities. */
    static final int PORT_2375 = 2375;
    static final int PORT_2376 = 2376;
    static final int PORT_2377 = 2377;
    static final int PORT_6443 = 6443;
    static final int PORT_10255 = 10255;
    static final int PORT_5000 = 5000;
    static final String SEVERITY_CRITICAL = "CRITICAL";
    static final String SEVERITY_HIGH = "HIGH";
    static final String SEVERITY_MEDIUM = "MEDIUM";
    static final String SEVERITY_LOW = "LOW";

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
    private final SnmpClient snmpClient;
    private final SnmpBridgeMapper snmpBridgeMapper;
    private final String snmpCommunity;
    private final boolean snmpEnabled;
    private final TraefikApiClient traefikClient;
    private final TraefikRouterMapper traefikRouterMapper;
    private final PortainerApiClient portainerClient;
    private final CAdvisorApiClient cadvisorClient;
    private final CAdvisorContainerMapper cadvisorMapper;
    private final Port8080Fingerprinter port8080Fingerprinter;
    private final boolean traefikEnabled;
    private final boolean portainerEnabled;
    private final boolean cadvisorEnabled;
    private final K8sApiClient k8sApiClient;
    private final KubeletApiClient kubeletApiClient;
    private final K8sPodMapper k8sPodMapper;
    private final boolean k8sEnabled;
    private final RegistryApiClient registryApiClient;
    private final RegistryCatalogMapper registryCatalogMapper;
    private final boolean registryEnabled;

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
            SnmpClient snmpClient,
            SnmpBridgeMapper snmpBridgeMapper,
            TraefikApiClient traefikClient,
            TraefikRouterMapper traefikRouterMapper,
            PortainerApiClient portainerClient,
            CAdvisorApiClient cadvisorClient,
            CAdvisorContainerMapper cadvisorMapper,
            Port8080Fingerprinter port8080Fingerprinter,
            K8sApiClient k8sApiClient,
            KubeletApiClient kubeletApiClient,
            K8sPodMapper k8sPodMapper,
            RegistryApiClient registryApiClient,
            RegistryCatalogMapper registryCatalogMapper,
            @Value("${castellum.docker.probe.connect-timeout-ms:2000}") int connectTimeoutMs,
            @Value("${castellum.docker.probe.read-timeout-ms:5000}") int readTimeoutMs,
            @Value("${castellum.docker.probe.max-concurrent:8}") int maxConcurrent,
            @Value("${castellum.docker.probe.snmp.community:public}") String snmpCommunity,
            @Value("${castellum.docker.probe.snmp.enabled:true}") boolean snmpEnabled,
            @Value("${castellum.docker.probe.traefik.enabled:true}") boolean traefikEnabled,
            @Value("${castellum.docker.probe.portainer.enabled:true}") boolean portainerEnabled,
            @Value("${castellum.docker.probe.cadvisor.enabled:true}") boolean cadvisorEnabled,
            @Value("${castellum.docker.probe.k8s.enabled:true}") boolean k8sEnabled,
            @Value("${castellum.docker.probe.registry.enabled:true}") boolean registryEnabled) {
        this(deviceUpsertService, deviceRepository, dockerDiscoveryService, apiClient,
             networkMapper, containerListMapper, inspectParser, networkServiceRepository,
             auditService, snmpClient, snmpBridgeMapper, snmpCommunity, snmpEnabled,
             traefikClient, traefikRouterMapper, portainerClient, cadvisorClient, cadvisorMapper,
             port8080Fingerprinter, traefikEnabled, portainerEnabled, cadvisorEnabled,
             k8sApiClient, kubeletApiClient, k8sPodMapper, k8sEnabled,
             registryApiClient, registryCatalogMapper, registryEnabled,
             maxConcurrent,
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

    /** Test seam constructor — caller supplies reachability predicate and all probe seams. */
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
            SnmpClient snmpClient,
            SnmpBridgeMapper snmpBridgeMapper,
            String snmpCommunity,
            boolean snmpEnabled,
            TraefikApiClient traefikClient,
            TraefikRouterMapper traefikRouterMapper,
            PortainerApiClient portainerClient,
            CAdvisorApiClient cadvisorClient,
            CAdvisorContainerMapper cadvisorMapper,
            Port8080Fingerprinter port8080Fingerprinter,
            boolean traefikEnabled,
            boolean portainerEnabled,
            boolean cadvisorEnabled,
            K8sApiClient k8sApiClient,
            KubeletApiClient kubeletApiClient,
            K8sPodMapper k8sPodMapper,
            boolean k8sEnabled,
            RegistryApiClient registryApiClient,
            RegistryCatalogMapper registryCatalogMapper,
            boolean registryEnabled,
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
        this.snmpClient = snmpClient;
        this.snmpBridgeMapper = snmpBridgeMapper;
        this.snmpCommunity = snmpCommunity;
        this.snmpEnabled = snmpEnabled;
        this.traefikClient = traefikClient;
        this.traefikRouterMapper = traefikRouterMapper;
        this.portainerClient = portainerClient;
        this.cadvisorClient = cadvisorClient;
        this.cadvisorMapper = cadvisorMapper;
        this.port8080Fingerprinter = port8080Fingerprinter;
        this.traefikEnabled = traefikEnabled;
        this.portainerEnabled = portainerEnabled;
        this.cadvisorEnabled = cadvisorEnabled;
        this.k8sApiClient = k8sApiClient;
        this.kubeletApiClient = kubeletApiClient;
        this.k8sPodMapper = k8sPodMapper;
        this.k8sEnabled = k8sEnabled;
        this.registryApiClient = registryApiClient;
        this.registryCatalogMapper = registryCatalogMapper;
        this.registryEnabled = registryEnabled;
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
                        raiseExposureFinding(selfDevice.get().getId(), PORT_2375, "tcp",
                        PROTOCOL_FAMILY_DOCKER_EXPOSURE, SEVERITY_CRITICAL);
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
        } else if (reachable.test(new HostPort(ip, PORT_2376))) {
            // :2376 (TLS) — finding only, no extraction
            log.info("DockerHostProbeService: {} :2376 reachable — raising HIGH finding (no extraction)", ip);
            probe2376or2377(ip, PORT_2376, startMs);
        } else if (reachable.test(new HostPort(ip, PORT_2377))) {
            // :2377 (Swarm) — finding only, no extraction
            log.info("DockerHostProbeService: {} :2377 reachable — raising HIGH finding (no extraction)", ip);
            probe2376or2377(ip, PORT_2377, startMs);
        } else {
            // All ports closed — fast no-op
            log.debug("DockerHostProbeService: {} all probe ports closed — no-op", ip);
        }

        // SNMP probe: unconditional per host (runs regardless of Docker port state)
        if (snmpEnabled) {
            probeSnmp(ip, startMs);
        }

        // HTTP-UI probes: :8080 (Traefik/cAdvisor fingerprinted) and :9000/:9443 (Portainer)
        if ((traefikEnabled || cadvisorEnabled) && reachable.test(new HostPort(ip, 8080))) {
            probe8080(ip, startMs);
        }
        if (portainerEnabled) {
            if (reachable.test(new HostPort(ip, 9000))) {
                probePortainer(ip, 9000, startMs);
            } else if (reachable.test(new HostPort(ip, 9443))) {
                probePortainer(ip, 9443, startMs);
            }
        }

        // Kubernetes API server :6443 + kubelet read-only :10255
        if (k8sEnabled) {
            probeK8s(ip, startMs);
        }

        // Docker Registry :5000
        if (registryEnabled) {
            if (reachable.test(new HostPort(ip, PORT_5000))) {
                probeRegistry(ip, startMs);
            }
        }
    }

    private void probe2375(String ip, long startMs) {
        try {
            // Pull container list
            Optional<String> containerListOpt = apiClient.getContainers(ip, PORT_2375);
            if (containerListOpt.isEmpty()) {
                log.debug("DockerHostProbeService: {} :2375 container list empty — raising finding only", ip);
                raiseFindingForExistingDevice(ip, PORT_2375, "tcp",
                    PROTOCOL_FAMILY_DOCKER_EXPOSURE, SEVERITY_CRITICAL);
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

            // Wire F2 NB1: recover gateway/subnet/network_name for networks with no running
            // container representative (gateway-only, no phantom containers — R2).
            // Mirrors the probeSnmp mapBridges → ingestNetworks pattern.
            Optional<String> networksOpt = apiClient.getNetworks(ip, PORT_2375);
            if (networksOpt.isPresent()) {
                var attachments = networkMapper.mapNetworks(networksOpt.get());
                if (!attachments.isEmpty()) {
                    dockerDiscoveryService.ingestNetworks(attachments, origin, now);
                }
            }

            // Raise CRITICAL posture finding for the probed host device
            raiseFindingForExistingDevice(ip, PORT_2375, "tcp",
                PROTOCOL_FAMILY_DOCKER_EXPOSURE, SEVERITY_CRITICAL);

            emitAuditSuccess(ip, PORT_2375, "success containers=" + containers.size(), startMs);

        } catch (Exception e) {
            log.warn("DockerHostProbeService: {} :2375 probe failed: {}", ip, e.getMessage());
            emitAuditFailure(ip, PORT_2375, e, startMs);
        }
    }

    private void probe2376or2377(String ip, int port, long startMs) {
        try {
            raiseFindingForExistingDevice(ip, port, "tcp",
                PROTOCOL_FAMILY_DOCKER_EXPOSURE, SEVERITY_HIGH);
            emitAuditSuccess(ip, port, "reachable-tls-no-extraction", startMs);
        } catch (Exception e) {
            log.warn("DockerHostProbeService: {} :{} finding upsert failed: {}", ip, port, e.getMessage());
            emitAuditFailure(ip, port, e, startMs);
        }
    }

    /**
     * Probe SNMP on the given host — unconditional per-host, runs after Docker port dispatch.
     *
     * <p>Walks bridges with the configured community first; if the "public" community answers,
     * raises a LOW udp/161 finding. Injects SNMP-discovered gateways via
     * {@link DockerDiscoveryService#ingestNetworks} (subnets-only, no phantom containers).
     *
     * <p>READ-ONLY: only SNMP GET/GETBULK via {@link SnmpClient} (no SET). (R9 per-host try/catch)
     */
    private void probeSnmp(String ip, long startMs) {
        try {
            // Walk interfaces + addresses with configured community
            Optional<List<SnmpClient.SnmpRow>> ifaceOpt =
                snmpClient.walkInterfaces(ip, snmpCommunity);
            Optional<List<SnmpClient.SnmpAddr>> addrOpt =
                snmpClient.walkIpAddresses(ip, snmpCommunity);

            if (ifaceOpt.isPresent() && !ifaceOpt.get().isEmpty()) {
                // Map to bridge attachments and ingest gateway-only (subnets-only, R2)
                List<io.castellum.discovery.DockerContainer.DockerNetworkAttachment> attachments =
                    snmpBridgeMapper.mapBridges(ifaceOpt.get(), addrOpt.orElse(List.of()));
                if (!attachments.isEmpty()) {
                    OriginContext origin = OriginContext.of(ip, ip);
                    dockerDiscoveryService.ingestNetworks(attachments, origin, Instant.now());
                    log.info("DockerHostProbeService: {} SNMP bridges recovered: {}", ip, attachments.size());
                }
            }

            // Check if "public" community answers — raise LOW udp/161 finding if so
            Optional<List<SnmpClient.SnmpRow>> publicWalk =
                snmpClient.walkInterfaces(ip, "public");
            if (publicWalk.isPresent() && !publicWalk.get().isEmpty()) {
                log.info("DockerHostProbeService: {} SNMP 'public' community answers — raising LOW udp/161 finding", ip);
                // Re-walk with public to ingest bridges
                Optional<List<SnmpClient.SnmpAddr>> publicAddr =
                    snmpClient.walkIpAddresses(ip, "public");
                List<io.castellum.discovery.DockerContainer.DockerNetworkAttachment> pubAttachments =
                    snmpBridgeMapper.mapBridges(publicWalk.get(), publicAddr.orElse(List.of()));
                if (!pubAttachments.isEmpty()) {
                    OriginContext origin = OriginContext.of(ip, ip);
                    dockerDiscoveryService.ingestNetworks(pubAttachments, origin, Instant.now());
                }
                raiseFindingForExistingDevice(ip, 161, "udp",
                    PROTOCOL_FAMILY_SNMP_EXPOSURE, SEVERITY_LOW);
            }

            emitAuditSuccess(ip, 161, "snmp-probe", startMs);
        } catch (Exception e) {
            log.warn("DockerHostProbeService: {} SNMP probe failed: {}", ip, e.getMessage());
            emitAuditFailure(ip, 161, e, startMs);
        }
    }

    /**
     * Probe port 8080 — fingerprint Traefik vs cAdvisor vs UNKNOWN (R3).
     *
     * <p>UNKNOWN → no extraction, no finding (required disambiguation test).
     * READ-ONLY: GET-only via TraefikApiClient/CAdvisorApiClient.
     */
    private void probe8080(String ip, long startMs) {
        try {
            Port8080Fingerprinter.Identity identity = port8080Fingerprinter.identify(ip, 8080);
            switch (identity) {
                case TRAEFIK -> {
                    log.info("DockerHostProbeService: {}:8080 is TRAEFIK — fingerprinted (traefikEnabled={})", ip, traefikEnabled);
                    emitAuditSuccess(ip, 8080, "traefik", startMs);
                    if (traefikEnabled) {
                        Optional<String> routersOpt = traefikClient.getRouters(ip, 8080);
                        Optional<String> servicesOpt = traefikClient.getServices(ip, 8080);
                        if (routersOpt.isPresent()) {
                            traefikRouterMapper.backendContainerNames(
                                routersOpt.get(), servicesOpt.orElse(null));
                        }
                        raiseFindingForExistingDevice(ip, 8080, "tcp",
                            PROTOCOL_FAMILY_TRAEFIK_EXPOSURE, SEVERITY_MEDIUM);
                    }
                }
                case CADVISOR -> {
                    log.info("DockerHostProbeService: {}:8080 is CADVISOR — fingerprinted (cadvisorEnabled={})", ip, cadvisorEnabled);
                    emitAuditSuccess(ip, 8080, "cadvisor", startMs);
                    if (cadvisorEnabled) {
                        Optional<String> subOpt = cadvisorClient.getSubcontainers(ip, 8080);
                        if (subOpt.isPresent()) {
                            cadvisorMapper.containerNames(subOpt.get());
                        }
                        raiseFindingForExistingDevice(ip, 8080, "tcp",
                            PROTOCOL_FAMILY_CADVISOR_EXPOSURE, SEVERITY_MEDIUM);
                    }
                }
                case UNKNOWN -> {
                    // R3: unknown fingerprint → no extraction, no finding
                    log.debug("DockerHostProbeService: {}:8080 fingerprint UNKNOWN — no finding (R3)", ip);
                    emitAuditSuccess(ip, 8080, "unknown-fingerprint", startMs);
                }
            }
        } catch (Exception e) {
            log.warn("DockerHostProbeService: {} :8080 probe failed: {}", ip, e.getMessage());
            emitAuditFailure(ip, 8080, e, startMs);
        }
    }

    /**
     * Probe Portainer on the given port (:9000 or :9443) — detect always, extract only no-auth (R10).
     *
     * <p>getStatus = detection; getEndpoints = extraction only when no-auth (401 → empty → skip).
     * READ-ONLY: GET-only, no login/POST.
     */
    private void probePortainer(String ip, int port, long startMs) {
        try {
            Optional<String> statusOpt = portainerClient.getStatus(ip, port);
            if (statusOpt.isEmpty()) {
                log.debug("DockerHostProbeService: {}:{} not a Portainer instance", ip, port);
                return;
            }
            log.info("DockerHostProbeService: {}:{} is PORTAINER — raising MEDIUM finding", ip, port);
            raiseFindingForExistingDevice(ip, port, "tcp",
                PROTOCOL_FAMILY_PORTAINER_EXPOSURE, SEVERITY_MEDIUM);

            // Extract endpoints only if no-auth (401 → empty → no extraction)
            Optional<String> endpointsOpt = portainerClient.getEndpoints(ip, port);
            if (endpointsOpt.isPresent() && !endpointsOpt.get().isBlank()) {
                log.info("DockerHostProbeService: {}:{} Portainer endpoints accessible (no-auth)", ip, port);
                // Endpoints are logged/recorded but not upserted as devices (informational only)
            }

            emitAuditSuccess(ip, port, "portainer", startMs);
        } catch (Exception e) {
            log.warn("DockerHostProbeService: {} :{} Portainer probe failed: {}", ip, port, e.getMessage());
            emitAuditFailure(ip, port, e, startMs);
        }
    }

    /**
     * Probe Kubernetes API server on :6443 and kubelet read-only port on :10255.
     *
     * <p><b>:6443 logic:</b>
     * <ul>
     *   <li>If :6443 reachable AND anonymous {@code getPods} returns a body → CRITICAL finding
     *       (anonymous pod read succeeded) + ingest pod topology.</li>
     *   <li>If :6443 reachable BUT getter returns empty (401/403) → HIGH finding-only; NO data
     *       extracted, NO retry (R3).</li>
     * </ul>
     *
     * <p><b>:10255 logic (independent):</b>
     * <ul>
     *   <li>If :10255 reachable AND {@code getPods} returns a body → HIGH finding + ingest pods.</li>
     * </ul>
     *
     * <p>READ-ONLY: GET-only via {@link K8sApiClient} and {@link KubeletApiClient}.
     */
    private void probeK8s(String ip, long startMs) {
        // --- :6443 Kubernetes API server ---
        if (reachable.test(new HostPort(ip, PORT_6443))) {
            try {
                Optional<String> podsOpt = k8sApiClient.getPods(ip, PORT_6443);
                if (podsOpt.isPresent()) {
                    // Anonymous read succeeded → CRITICAL
                    log.info("DockerHostProbeService: {} :6443 anonymous pod read succeeded — CRITICAL", ip);
                    List<io.castellum.discovery.DockerContainer> pods =
                        k8sPodMapper.mapPods(podsOpt.get());
                    if (!pods.isEmpty()) {
                        io.castellum.discovery.OriginContext origin =
                            io.castellum.discovery.OriginContext.of(ip, ip);
                        dockerDiscoveryService.ingest(pods, origin, Instant.now());
                    }
                    raiseFindingForExistingDevice(ip, PORT_6443, "tcp",
                        PROTOCOL_FAMILY_K8S_API_EXPOSURE, SEVERITY_CRITICAL);
                } else {
                    // Getter returned empty — 401/403 back-off (no retry, R3)
                    log.info("DockerHostProbeService: {} :6443 reachable but 401/403 (auth required) — HIGH finding only", ip);
                    raiseFindingForExistingDevice(ip, PORT_6443, "tcp",
                        PROTOCOL_FAMILY_K8S_API_EXPOSURE, SEVERITY_HIGH);
                }
                emitAuditSuccess(ip, PORT_6443, "k8s-api", startMs);
            } catch (Exception e) {
                log.warn("DockerHostProbeService: {} :6443 probe failed: {}", ip, e.getMessage());
                emitAuditFailure(ip, PORT_6443, e, startMs);
            }
        }

        // --- :10255 Kubelet read-only port (independent of :6443 result) ---
        if (reachable.test(new HostPort(ip, PORT_10255))) {
            try {
                Optional<String> kubeletPodsOpt = kubeletApiClient.getPods(ip, PORT_10255);
                if (kubeletPodsOpt.isPresent()) {
                    log.info("DockerHostProbeService: {} :10255 kubelet pods accessible — HIGH", ip);
                    List<io.castellum.discovery.DockerContainer> kubeletPods =
                        k8sPodMapper.mapPods(kubeletPodsOpt.get());
                    if (!kubeletPods.isEmpty()) {
                        io.castellum.discovery.OriginContext origin =
                            io.castellum.discovery.OriginContext.of(ip, ip);
                        dockerDiscoveryService.ingest(kubeletPods, origin, Instant.now());
                    }
                    raiseFindingForExistingDevice(ip, PORT_10255, "tcp",
                        PROTOCOL_FAMILY_KUBELET_RO_EXPOSURE, SEVERITY_HIGH);
                } else {
                    log.info("DockerHostProbeService: {} :10255 reachable but no pods returned — finding only", ip);
                    raiseFindingForExistingDevice(ip, PORT_10255, "tcp",
                        PROTOCOL_FAMILY_KUBELET_RO_EXPOSURE, SEVERITY_HIGH);
                }
                emitAuditSuccess(ip, PORT_10255, "kubelet-ro", startMs);
            } catch (Exception e) {
                log.warn("DockerHostProbeService: {} :10255 probe failed: {}", ip, e.getMessage());
                emitAuditFailure(ip, PORT_10255, e, startMs);
            }
        }
    }

    /**
     * Probe Docker Registry on :5000.
     *
     * <p>On a successful {@code _catalog} response (unauthenticated) → write the image inventory
     * blob to the probed host's {@code registry_images} column (HOST METADATA — NOT per-image
     * topology rows, R6) AND raise a MEDIUM finding. A 401/empty → no extraction, no finding
     * (an authenticated registry is not the MEDIUM-exposure case).
     *
     * <p>READ-ONLY: GET-only via {@link RegistryApiClient}.
     */
    private void probeRegistry(String ip, long startMs) {
        try {
            Optional<String> catalogOpt = registryApiClient.getCatalog(ip, PORT_5000);
            if (catalogOpt.isPresent()) {
                log.info("DockerHostProbeService: {} :5000 registry catalog accessible — MEDIUM", ip);
                List<String> repos = registryCatalogMapper.repositories(catalogOpt.get());
                // Enrich: for each repo, fetch tags and fold into name:tag entries
                List<String> imageEntries = new ArrayList<>();
                for (String repo : repos) {
                    Optional<String> tagsOpt = registryApiClient.getTags(ip, PORT_5000, repo);
                    if (tagsOpt.isPresent()) {
                        List<String> tagList = registryCatalogMapper.tags(tagsOpt.get());
                        // Cap tags per repo to MAX_TAGS_PER_REPO to prevent blob-DoS
                        List<String> cappedTags = tagList.size() > MAX_TAGS_PER_REPO
                                ? tagList.subList(0, MAX_TAGS_PER_REPO)
                                : tagList;
                        for (String tag : cappedTags) {
                            imageEntries.add(repo + ":" + tag);
                        }
                        if (tagList.isEmpty()) {
                            // No tags returned — fall back to bare repo name
                            imageEntries.add(repo);
                        }
                    } else {
                        // getTags not available — fall back to bare repo name
                        imageEntries.add(repo);
                    }
                }
                String blob = registryCatalogMapper.toInventoryBlob(imageEntries);
                // Write registry_images metadata to the probed host Device row (HOST METADATA only)
                persistRegistryImages(ip, blob);
                raiseFindingForExistingDevice(ip, PORT_5000, "tcp",
                    PROTOCOL_FAMILY_REGISTRY_EXPOSURE, SEVERITY_MEDIUM);
            } else {
                log.debug("DockerHostProbeService: {} :5000 registry auth required (401) — no extraction", ip);
                // 401 → no finding (authenticated registry is not the MEDIUM exposure case)
            }
            emitAuditSuccess(ip, PORT_5000, "registry", startMs);
        } catch (Exception e) {
            log.warn("DockerHostProbeService: {} :5000 registry probe failed: {}", ip, e.getMessage());
            emitAuditFailure(ip, PORT_5000, e, startMs);
        }
    }

    /**
     * Persist the {@code registry_images} metadata blob on the local-origin Device row for the
     * given IP (R6 — HOST METADATA on the Device row, NOT per-image topology rows).
     *
     * <p>Reuses the {@code (ip, "local")} lookup idiom from {@link #raiseFindingForExistingDevice}.
     * Skips silently if no inventory row exists for the IP.
     */
    private void persistRegistryImages(String ip, String blob) {
        Optional<Device> deviceOpt = deviceRepository.findByIpAddressAndOriginHostIp(ip, "local");
        if (deviceOpt.isEmpty()) {
            log.debug("DockerHostProbeService: no inventory row for {} — skipping registry_images write", ip);
            return;
        }
        Device device = deviceOpt.get();
        device.setRegistryImages(blob.isBlank() ? null : blob);
        deviceRepository.save(device);
    }

    /**
     * Raise a posture finding for the host device identified by the given IP.
     * If the host device does not exist in the inventory (not yet scan-discovered), skip.
     */
    private void raiseFindingForExistingDevice(String ip, int port, String protocol,
                                               String protocolFamily, String severity) {
        Optional<Device> deviceOpt = deviceRepository.findByIpAddressAndOriginHostIp(ip, "local");
        if (deviceOpt.isEmpty()) {
            log.debug("DockerHostProbeService: no inventory row for {} — skipping finding", ip);
            return;
        }
        raiseExposureFinding(deviceOpt.get().getId(), port, protocol, protocolFamily, severity);
    }

    /**
     * Upsert a posture finding row on the given device's (port, protocol) NetworkService.
     * Mirrors {@link io.castellum.ot.OtFingerprintService} L188-200.
     *
     * @param protocol       transport protocol ("tcp" or "udp")
     * @param protocolFamily one of the PROTOCOL_FAMILY_* constants
     */
    private void raiseExposureFinding(Long deviceId, int port, String protocol,
                                      String protocolFamily, String severity) {
        NetworkService svc = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(deviceId, port, protocol)
            .orElseGet(NetworkService::new);
        svc.setDeviceId(deviceId);
        svc.setPort(port);
        svc.setProtocol(protocol);
        svc.setName(FINDING_NAME);
        svc.setProtocolFamily(protocolFamily);
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
