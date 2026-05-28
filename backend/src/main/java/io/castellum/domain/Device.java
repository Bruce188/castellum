package io.castellum.domain;

import io.castellum.discovery.DiscoveryScope;
import io.castellum.discovery.DiscoverySource;
import io.castellum.risk.Criticality;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "device")
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false, unique = true)
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

    @Column(name = "os_name")
    private String osName;

    @Column(name = "os_accuracy")
    private Integer osAccuracy;

    @Column(name = "os_cpe")
    private String osCpe;

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

    public String getOsName() { return osName; }
    public void setOsName(String osName) { this.osName = osName; }

    public Integer getOsAccuracy() { return osAccuracy; }
    public void setOsAccuracy(Integer osAccuracy) { this.osAccuracy = osAccuracy; }

    public String getOsCpe() { return osCpe; }
    public void setOsCpe(String osCpe) { this.osCpe = osCpe; }

    public long getServiceCount() { return serviceCount; }

    /** Test-support setter — allows controller tests to stub a non-zero count on a mocked Device. */
    public void setServiceCount(long serviceCount) { this.serviceCount = serviceCount; }
}
