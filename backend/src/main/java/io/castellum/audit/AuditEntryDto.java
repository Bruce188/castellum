package io.castellum.audit;

import java.time.Instant;

public record AuditEntryDto(Long id, Instant occurredAt, String actor, String action,
                            String resourceType, String resourceId, String payload) {

    public static AuditEntryDto from(AuditLog row) {
        return new AuditEntryDto(row.getId(), row.getOccurredAt(), row.getActor(),
            row.getAction(), row.getResourceType(), row.getResourceId(), row.getPayload());
    }
}
