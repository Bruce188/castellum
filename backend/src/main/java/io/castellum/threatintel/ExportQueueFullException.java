package io.castellum.threatintel;

/**
 * Thrown by {@link ExportJobService#submit()} when the backing thread-pool executor
 * rejects the task (e.g., AbortPolicy fires on a saturated queue).
 *
 * <p>Mapped to HTTP 503 Service Unavailable by {@code GlobalExceptionHandler}.
 */
public class ExportQueueFullException extends RuntimeException {

    public ExportQueueFullException() {
        super("Export queue is full — try again later");
    }

    public ExportQueueFullException(String message) {
        super(message);
    }

    public ExportQueueFullException(String message, Throwable cause) {
        super(message, cause);
    }
}
