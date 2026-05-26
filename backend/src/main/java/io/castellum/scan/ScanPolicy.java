package io.castellum.scan;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * Cron-driven scan policy. ADMIN-managed via /api/scan-policy; ticked by
 * {@link ScanPolicyScheduler}.
 */
@Entity
@Table(name = "scan_policy")
public class ScanPolicy {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(name = "cron_expression", nullable = false)
    private String cronExpression;

    @Column(nullable = false)
    private String cidr;

    @Column(name = "scan_type", nullable = false)
    private String scanType;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "last_triggered_at")
    private Instant lastTriggeredAt;

    public ScanPolicy() {}

    public ScanPolicy(String name, String cronExpression, String cidr, String scanType, boolean enabled) {
        this.name = name;
        this.cronExpression = cronExpression;
        this.cidr = cidr;
        this.scanType = scanType;
        this.enabled = enabled;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getCronExpression() { return cronExpression; }
    public void setCronExpression(String cronExpression) { this.cronExpression = cronExpression; }

    public String getCidr() { return cidr; }
    public void setCidr(String cidr) { this.cidr = cidr; }

    public String getScanType() { return scanType; }
    public void setScanType(String scanType) { this.scanType = scanType; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getLastTriggeredAt() { return lastTriggeredAt; }
    public void setLastTriggeredAt(Instant lastTriggeredAt) { this.lastTriggeredAt = lastTriggeredAt; }
}
