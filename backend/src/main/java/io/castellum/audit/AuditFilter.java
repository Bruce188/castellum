package io.castellum.audit;

import java.time.Instant;

public record AuditFilter(Instant since, Instant until, String action, String actor, String resourceType) {}
