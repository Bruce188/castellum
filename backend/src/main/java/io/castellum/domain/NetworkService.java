package io.castellum.domain;

import jakarta.persistence.*;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.time.Instant;

@Entity
@Table(name = "service",
    uniqueConstraints = @UniqueConstraint(
        name = "service_dev_port_proto_unique",
        columnNames = {"device_id", "port", "protocol"}
    )
)
public class NetworkService {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "device_id", nullable = false)
    private Long deviceId;

    @Min(1)
    @Max(65535)
    @Column(nullable = false)
    private Integer port;

    @Column(nullable = false)
    private String protocol;

    private String name;

    private String version;

    @Column(name = "observed_at")
    private Instant observedAt;

    @Column(name = "vendor")
    private String vendor;

    @Column(name = "product")
    private String product;

    @Column(name = "protocol_family")
    private String protocolFamily;

    @Column(name = "cpe")
    private String cpe;

    /**
     * Posture severity for this service row when it represents a known exposure finding
     * (e.g. an exposed Docker Engine API on port 2375). Values follow the standard severity
     * vocabulary: CRITICAL, HIGH, MEDIUM, LOW, INFO. Null for normal service rows without a
     * posture finding — scoring falls back entirely to CVE-derived risk in DeviceRiskService.
     * Set by the Docker Host Probe (Phase 4). ADDITIVE — not a parallel findings store.
     */
    @Column(name = "posture_severity")
    private String postureSeverity;

    public NetworkService() {}

    public NetworkService(Long id, Long deviceId, Integer port, String protocol, String name, String version, Instant observedAt) {
        this.id = id;
        this.deviceId = deviceId;
        this.port = port;
        this.protocol = protocol;
        this.name = name;
        this.version = version;
        this.observedAt = observedAt;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getDeviceId() { return deviceId; }
    public void setDeviceId(Long deviceId) { this.deviceId = deviceId; }

    public Integer getPort() { return port; }
    public void setPort(Integer port) { this.port = port; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public Instant getObservedAt() { return observedAt; }
    public void setObservedAt(Instant observedAt) { this.observedAt = observedAt; }

    public String getVendor() { return vendor; }
    public void setVendor(String vendor) { this.vendor = vendor; }

    public String getProduct() { return product; }
    public void setProduct(String product) { this.product = product; }

    public String getProtocolFamily() { return protocolFamily; }
    public void setProtocolFamily(String protocolFamily) { this.protocolFamily = protocolFamily; }

    public String getCpe() { return cpe; }
    public void setCpe(String cpe) { this.cpe = cpe; }

    public String getPostureSeverity() { return postureSeverity; }
    public void setPostureSeverity(String postureSeverity) { this.postureSeverity = postureSeverity; }
}
