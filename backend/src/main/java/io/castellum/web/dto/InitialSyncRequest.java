package io.castellum.web.dto;

import java.time.Instant;

/**
 * Optional request body for {@code POST /api/admin/initial-sync} and
 * {@code POST /api/admin/full-backfill}.
 *
 * <p>Both fields are nullable — callers may omit the body entirely ({@code null} record)
 * or supply a partial body (e.g. only {@code since}). Use {@link #defaults()} to obtain
 * a fully-resolved request when no body was provided.
 *
 * <p>Accessor helpers {@link #effectiveSince()} and {@link #effectiveUntil()} null-coalesce
 * to {@code Instant.EPOCH} and {@code Instant.now()} respectively, matching the first-run
 * intent of pulling the entire NVD corpus.
 *
 * <p>{@code fullBackfill} — when {@code true}, the NVD sync path MUST call
 * {@code bulkPull(EPOCH, now)} unconditionally, bypassing any
 * {@code findMaxLastModified} short-circuit.  Defaults to {@code false} so that
 * existing callers that omit the field retain their current behaviour.
 */
public record InitialSyncRequest(Instant since, Instant until, Boolean fullBackfill) {

    /** Creates a fully-resolved default request: EPOCH → now(), fullBackfill=false. */
    public static InitialSyncRequest defaults() {
        return new InitialSyncRequest(Instant.EPOCH, Instant.now(), false);
    }

    /** Returns {@code since} if non-null, otherwise {@code Instant.EPOCH}. */
    public Instant effectiveSince() {
        return since != null ? since : Instant.EPOCH;
    }

    /** Returns {@code until} if non-null, otherwise {@code Instant.now()}. */
    public Instant effectiveUntil() {
        return until != null ? until : Instant.now();
    }

    /** Returns {@code true} when a forced full-corpus backfill was requested. */
    public boolean isFullBackfill() {
        return Boolean.TRUE.equals(fullBackfill);
    }
}
