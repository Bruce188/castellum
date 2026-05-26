package io.castellum.web.dto;

import java.time.Instant;

/**
 * Response body for {@code GET /api/admin/sync/status}.
 *
 * <p>{@code running} is {@code true} while an initial-sync job is executing.
 * {@code startedAt} is the timestamp when the current (or most recent) sync began,
 * or {@code null} if no sync has ever been triggered.
 */
public record SyncStatusResponse(boolean running, Instant startedAt) {}
