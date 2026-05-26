package io.castellum.discovery;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * JPA mapping for V11 {@code discovery_sweep} audit table. Each passive-discovery sweep
 * records start/finish timestamps, source(s), neighbor + device counts, who triggered it,
 * and an optional FK to {@code audit_log(id)} populated by {@link io.castellum.audit.AuditService}.
 *
 * <p>Flat {@code auditLogId} reference (no {@code @ManyToOne}) per
 * {@link io.castellum.cve.CveCpeMatch} precedent — keeps the entity hydration cost low and
 * decouples sweep persistence from the audit-log entity lifecycle.
 */
@Entity
@Table(name = "discovery_sweep")
public class DiscoverySweep {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "started_at", nullable = false)
    private Instant startedAt;

    @Column(name = "finished_at")
    private Instant finishedAt;

    @Column(nullable = false)
    private String source;

    @Column
    private String iface;

    @Column(name = "neighbor_count", nullable = false)
    private int neighborCount;

    @Column(name = "device_count", nullable = false)
    private int deviceCount;

    @Column(name = "triggered_by", nullable = false)
    private String triggeredBy;

    @Column(name = "audit_log_id")
    private Long auditLogId;

    @Column(nullable = false)
    private String status;

    public DiscoverySweep() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Instant getStartedAt() { return startedAt; }
    public void setStartedAt(Instant startedAt) { this.startedAt = startedAt; }

    public Instant getFinishedAt() { return finishedAt; }
    public void setFinishedAt(Instant finishedAt) { this.finishedAt = finishedAt; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public String getIface() { return iface; }
    public void setIface(String iface) { this.iface = iface; }

    public int getNeighborCount() { return neighborCount; }
    public void setNeighborCount(int neighborCount) { this.neighborCount = neighborCount; }

    public int getDeviceCount() { return deviceCount; }
    public void setDeviceCount(int deviceCount) { this.deviceCount = deviceCount; }

    public String getTriggeredBy() { return triggeredBy; }
    public void setTriggeredBy(String triggeredBy) { this.triggeredBy = triggeredBy; }

    public Long getAuditLogId() { return auditLogId; }
    public void setAuditLogId(Long auditLogId) { this.auditLogId = auditLogId; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}
