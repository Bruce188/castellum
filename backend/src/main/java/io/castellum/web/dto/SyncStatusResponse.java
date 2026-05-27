package io.castellum.web.dto;

import java.time.Instant;

/**
 * Response body for {@code GET /api/admin/sync/status}.
 *
 * <p>{@code running} is {@code true} while an initial-sync job is executing.
 * {@code startedAt} is the timestamp when the current (or most recent) sync began,
 * or {@code null} if no sync has ever been triggered.
 * {@code lastCompletedAt} is the timestamp of the last completed sync (in-memory or
 * reconstructed from the audit log after restart), or {@code null} if never completed.
 * {@code lastError} holds the failure message from the last run, or {@code null} on success.
 */
public record SyncStatusResponse(
        boolean running,
        Instant startedAt,
        Instant lastCompletedAt,
        String lastError) {}
