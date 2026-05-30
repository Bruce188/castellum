package io.castellum.domain;

import io.castellum.discovery.DeviceRole;
import io.castellum.discovery.DiscoveryScope;
import io.castellum.discovery.DiscoverySource;
import io.castellum.discovery.RoleConfidence;
import io.castellum.risk.Criticality;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "device",
    uniqueConstraints = @UniqueConstraint(
        name = "device_ip_origin_unique",
        columnNames = {"ip_address", "origin_host_ip"}
    )
)
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false)
    private String ipAddress;

    private String hostname;

    @Column(name = "mac_address")
    private String macAddress;

    @Column(name = "first_seen")
    private Instant firstSeen;

    @Column(name = "last_seen")
    private Instant lastSeen;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Criticality criticality = Criticality.MEDIUM;

    @Enumerated(EnumType.STRING)
    @Column(name = "discovery_scope", nullable = false)
    private DiscoveryScope discoveryScope = DiscoveryScope.HOME;

    @Column(name = "last_seen_iface")
    private String lastSeenIface;

    /** Most recent discovery source that observed this device. Last-writer-wins (mirrors lastSeen). */
    @Enumerated(EnumType.STRING)
    @Column(name = "discovery_source")
    private DiscoverySource discoverySource;

    /**
     * Functional role classification populated by {@code DeviceRoleClassifier} at upsert time.
     * Default {@code UNKNOWN} covers rows inserted before V26 and devices whose signals are
     * ambiguous. NOT NULL — the entity default keeps manual POST safe without a controller change.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "device_role", nullable = false)
    private DeviceRole deviceRole = DeviceRole.UNKNOWN;

    /**
     * Confidence level of the {@link #deviceRole} classification.
     * {@link RoleConfidence#HIGH} = deterministic rule / API-confirmed container;
     * {@link RoleConfidence#LOW} = macvlan sweep heuristic with known false-positive risk.
     * NOT NULL — entity default {@code HIGH} keeps all existing rows correct on V28 migration.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "role_confidence", nullable = false)
    private RoleConfidence roleConfidence = RoleConfidence.HIGH;

    /**
     * Compact inventory of Docker registry images served by this device (host metadata only).
     * Populated by the registry probe ({@code :5000 GET /v2/_catalog}). Nullable — only set
     * when the host is confirmed to run a Docker registry with an unauthenticated catalog.
     * NOT a per-image topology row: stored as a delimited blob on the host device row.
     */
    @Column(name = "registry_images")
    private String registryImages;

    @Column(name = "publishes_host_port", nullable = false)
    private boolean publishesHostPort = false;

    @Column(name = "os_name")
    private String osName;

    @Column(name = "os_accuracy")
    private Integer osAccuracy;

    @Column(name = "os_cpe")
    private String osCpe;

    /** Scan that first discovered this device. Set on INSERT during a scan; NULL for pre-V25 and non-scan devices. */
    @Column(name = "discovered_by_scan_id")
    private Long discoveredByScanId;

    /** Scan that most recently observed this device. Set on INSERT and UPDATE during a scan; last-writer-wins. NULL for pre-V25 and non-scan devices. */
    @Column(name = "last_seen_by_scan_id")
    private Long lastSeenByScanId;

    /**
     * IP address of the host from which this device was discovered.
     * Value {@code "local"} means the device was observed by the local castellum agent (the
     * default for all ARP/NMAP/Docker-CLI/passive discovery paths). A remote docker probe
     * writes the probed host's IP so the same container IP (e.g. 172.17.0.2) from two different
     * hosts becomes two distinct device rows under the composite UNIQUE(ip_address, origin_host_ip).
     * NOT NULL — entity default {@code "local"} keeps all existing insert paths safe.
     */
    @Column(name = "origin_host_ip", nullable = false)
    private String originHostIp = "local";

    /**
     * Human-readable hostname of the origin host (optional). Null for local discovery and
     * when the hostname is unknown at probe time.
     */
    @Column(name = "origin_host_name")
    private String originHostName;

    /**
     * Count of network services observed on this device. Computed at entity-load
     * time via the Hibernate formula; not persisted (no Flyway migration needed).
     * Uses the physical table name {@code service} and column {@code device_id}
     * (verified in V2__create_service.sql across both Postgres and H2 profiles).
     */
    @org.hibernate.annotations.Formula("(select count(*) from service s where s.device_id = id)")
    private long serviceCount;

    public Device() {}

    public Device(Long id, String ipAddress, String hostname, String macAddress, Instant firstSeen, Instant lastSeen) {
        this.id = id;
        this.ipAddress = ipAddress;
        this.hostname = hostname;
        this.macAddress = macAddress;
        this.firstSeen = firstSeen;
        this.lastSeen = lastSeen;
    }

    public Device(Long id, String ipAddress, String hostname, String macAddress, Instant firstSeen, Instant lastSeen, Criticality criticality) {
        this.id = id;
        this.ipAddress = ipAddress;
        this.hostname = hostname;
        this.macAddress = macAddress;
        this.firstSeen = firstSeen;
        this.lastSeen = lastSeen;
        this.criticality = criticality;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }

    public String getMacAddress() { return macAddress; }
    public void setMacAddress(String macAddress) { this.macAddress = macAddress; }

    public Instant getFirstSeen() { return firstSeen; }
    public void setFirstSeen(Instant firstSeen) { this.firstSeen = firstSeen; }

    public Instant getLastSeen() { return lastSeen; }
    public void setLastSeen(Instant lastSeen) { this.lastSeen = lastSeen; }

    public Criticality getCriticality() { return criticality; }
    public void setCriticality(Criticality criticality) { this.criticality = criticality; }

    public DiscoveryScope getDiscoveryScope() { return discoveryScope; }
    public void setDiscoveryScope(DiscoveryScope discoveryScope) { this.discoveryScope = discoveryScope; }

    public String getLastSeenIface() { return lastSeenIface; }
    public void setLastSeenIface(String lastSeenIface) { this.lastSeenIface = lastSeenIface; }

    public DiscoverySource getDiscoverySource() { return discoverySource; }
    public void setDiscoverySource(DiscoverySource discoverySource) { this.discoverySource = discoverySource; }

    public DeviceRole getDeviceRole() { return deviceRole; }
    public void setDeviceRole(DeviceRole deviceRole) { this.deviceRole = deviceRole; }

    public RoleConfidence getRoleConfidence() { return roleConfidence; }
    public void setRoleConfidence(RoleConfidence roleConfidence) { this.roleConfidence = roleConfidence; }

    public String getRegistryImages() { return registryImages; }
    public void setRegistryImages(String registryImages) { this.registryImages = registryImages; }

    public boolean isPublishesHostPort() { return publishesHostPort; }
    public void setPublishesHostPort(boolean publishesHostPort) { this.publishesHostPort = publishesHostPort; }

    public String getOsName() { return osName; }
    public void setOsName(String osName) { this.osName = osName; }

    public Integer getOsAccuracy() { return osAccuracy; }
    public void setOsAccuracy(Integer osAccuracy) { this.osAccuracy = osAccuracy; }

    public String getOsCpe() { return osCpe; }
    public void setOsCpe(String osCpe) { this.osCpe = osCpe; }

    public Long getDiscoveredByScanId() { return discoveredByScanId; }
    public void setDiscoveredByScanId(Long discoveredByScanId) { this.discoveredByScanId = discoveredByScanId; }

    public Long getLastSeenByScanId() { return lastSeenByScanId; }
    public void setLastSeenByScanId(Long lastSeenByScanId) { this.lastSeenByScanId = lastSeenByScanId; }

    public String getOriginHostIp() { return originHostIp; }
    public void setOriginHostIp(String originHostIp) { this.originHostIp = originHostIp; }

    public String getOriginHostName() { return originHostName; }
    public void setOriginHostName(String originHostName) { this.originHostName = originHostName; }

    public long getServiceCount() { return serviceCount; }

    /** Test-support setter — allows controller tests to stub a non-zero count on a mocked Device. */
    public void setServiceCount(long serviceCount) { this.serviceCount = serviceCount; }
}
