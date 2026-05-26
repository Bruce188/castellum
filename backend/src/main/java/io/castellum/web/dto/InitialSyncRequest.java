package io.castellum.web.dto;

import java.time.Instant;

/**
 * Optional request body for {@code POST /api/admin/initial-sync}.
 *
 * <p>Both fields are nullable — callers may omit the body entirely ({@code null} record)
 * or supply a partial body (e.g. only {@code since}). Use {@link #defaults()} to obtain
 * a fully-resolved request when no body was provided.
 *
 * <p>Accessor helpers {@link #effectiveSince()} and {@link #effectiveUntil()} null-coalesce
 * to {@code Instant.EPOCH} and {@code Instant.now()} respectively, matching the first-run
 * intent of pulling the entire NVD corpus.
 */
public record InitialSyncRequest(Instant since, Instant until) {

    /** Creates a fully-resolved default request: EPOCH → now(). */
    public static InitialSyncRequest defaults() {
        return new InitialSyncRequest(Instant.EPOCH, Instant.now());
    }

    /** Returns {@code since} if non-null, otherwise {@code Instant.EPOCH}. */
    public Instant effectiveSince() {
        return since != null ? since : Instant.EPOCH;
    }

    /** Returns {@code until} if non-null, otherwise {@code Instant.now()}. */
    public Instant effectiveUntil() {
        return until != null ? until : Instant.now();
    }
}
