package io.castellum.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "scan")
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String cidr;

    @Column(name = "scan_type", nullable = false)
    private String scanType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScanStatus status = ScanStatus.PENDING;

    @Column(name = "requested_at", nullable = false)
    private Instant requestedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "failure_reason")
    private String failureReason;

    public Scan() {}

    public Scan(Long id, String cidr, String scanType, ScanStatus status, Instant requestedAt, Instant completedAt) {
        this.id = id;
        this.cidr = cidr;
        this.scanType = scanType;
        this.status = status;
        this.requestedAt = requestedAt;
        this.completedAt = completedAt;
    }

    public Scan(Long id, String cidr, String scanType, ScanStatus status, Instant requestedAt, Instant completedAt, String failureReason) {
        this.id = id;
        this.cidr = cidr;
        this.scanType = scanType;
        this.status = status;
        this.requestedAt = requestedAt;
        this.completedAt = completedAt;
        this.failureReason = failureReason;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getCidr() { return cidr; }
    public void setCidr(String cidr) { this.cidr = cidr; }

    public String getScanType() { return scanType; }
    public void setScanType(String scanType) { this.scanType = scanType; }

    public ScanStatus getStatus() { return status; }
    public void setStatus(ScanStatus status) { this.status = status; }

    public Instant getRequestedAt() { return requestedAt; }
    public void setRequestedAt(Instant requestedAt) { this.requestedAt = requestedAt; }

    public Instant getCompletedAt() { return completedAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }

    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }
}
