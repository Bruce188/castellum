package io.castellum.graph;

/**
 * Thrown by {@link GraphBuilder#build()} when the device count exceeds
 * {@code castellum.graph.max-devices}. Surfaced as HTTP 503 by
 * {@code GlobalExceptionHandler}.
 */
public class GraphTooLargeException extends IllegalStateException {

    public GraphTooLargeException(int actual, int cap) {
        super("device count " + actual + " exceeds castellum.graph.max-devices=" + cap);
    }
}
