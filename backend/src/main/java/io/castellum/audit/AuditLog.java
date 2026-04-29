package io.castellum.audit;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_log")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Column(nullable = false)
    private String actor;

    @Column(nullable = false)
    private String action;

    @Column(name = "resource_type", nullable = false)
    private String resourceType;

    @Column(name = "resource_id")
    private String resourceId;

    @Column
    private String payload;

    protected AuditLog() {}

    public AuditLog(Instant occurredAt, String actor, String action, String resourceType, String resourceId, String payload) {
        this.occurredAt = occurredAt;
        this.actor = actor;
        this.action = action;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.payload = payload;
    }

    public Long getId() { return id; }
    public Instant getOccurredAt() { return occurredAt; }
    public String getActor() { return actor; }
    public String getAction() { return action; }
    public String getResourceType() { return resourceType; }
    public String getResourceId() { return resourceId; }
    public String getPayload() { return payload; }
}
