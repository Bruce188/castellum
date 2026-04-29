package io.castellum.threatintel;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "threat_intel_push")
public class ThreatIntelPushRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "push_target", nullable = false)
    private String pushTarget;

    @Column(name = "bundle_id", nullable = false)
    private String bundleId;

    @Column(name = "status_code")
    private Integer statusCode;

    @Column(name = "response_excerpt")
    private String responseExcerpt;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Column(name = "audit_log_id")
    private Long auditLogId;

    public ThreatIntelPushRecord() {}

    public ThreatIntelPushRecord(String pushTarget, String bundleId, Integer statusCode,
                                  String responseExcerpt, Instant occurredAt, Long auditLogId) {
        this.pushTarget = pushTarget;
        this.bundleId = bundleId;
        this.statusCode = statusCode;
        this.responseExcerpt = responseExcerpt;
        this.occurredAt = occurredAt;
        this.auditLogId = auditLogId;
    }

    public Long getId() { return id; }
    public String getPushTarget() { return pushTarget; }
    public String getBundleId() { return bundleId; }
    public Integer getStatusCode() { return statusCode; }
    public String getResponseExcerpt() { return responseExcerpt; }
    public Instant getOccurredAt() { return occurredAt; }
    public Long getAuditLogId() { return auditLogId; }
}
