package io.castellum.threatintel;

/**
 * Test-scope placeholder for the domain exception the implementer must create in
 * {@code src/main}.  This class lives in {@code src/test} only so that the red-phase
 * tests compile and fail at runtime (not at compile time).
 *
 * <p>The implementer MUST create
 * {@code src/main/java/io/castellum/threatintel/ExportQueueFullException.java} — at
 * that point this test-scope copy is removed (or becomes redundant and can be deleted).
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
