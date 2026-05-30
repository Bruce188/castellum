package io.castellum.threatintel;

import java.time.Instant;

/**
 * Immutable snapshot of an async bundle-export job.
 *
 * <p>Constructor field order (id, status, objectCount, bundleId, filePath, error, submittedAt)
 * is load-bearing — tests instantiate directly in this order.
 */
public record ExportJob(
        String id,
        Status status,
        int objectCount,
        String bundleId,
        String filePath,
        String error,
        Instant submittedAt
) {

    public enum Status {
        PENDING,
        RUNNING,
        DONE,
        FAILED
    }
}
