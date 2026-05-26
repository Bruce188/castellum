package io.castellum.web.dto;

import java.time.Instant;

/**
 * Response body for {@code POST /api/admin/initial-sync}.
 *
 * <p>{@code status} is one of:
 * <ul>
 *   <li>{@code "started"} — the background job was submitted successfully.
 *   <li>{@code "already-running"} — a sync is already in flight; this request was no-op'd.
 *       The {@code startedAt} field reflects when the in-flight sync began.
 * </ul>
 */
public record InitialSyncResponse(String status, Instant startedAt) {}
