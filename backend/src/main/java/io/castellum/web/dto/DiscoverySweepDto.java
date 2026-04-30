package io.castellum.web.dto;

import java.time.Instant;

/**
 * Read-only DTO for {@code GET /api/discovery/sweeps}. Mirrors the
 * {@link io.castellum.discovery.DiscoverySweep} entity shape but stays in the
 * web-DTO package so the entity is never exposed to clients.
 */
public record DiscoverySweepDto(
    Long id,
    Instant startedAt,
    Instant finishedAt,
    String source,
    String iface,
    int neighborCount,
    int deviceCount,
    String triggeredBy,
    Long auditLogId,
    String status
) {}
