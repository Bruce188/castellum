package io.castellum.threatintel;

/** Thrown when the integration probe cannot connect to the target (connection refused, host unreachable). */
public final class IntegrationProbeUnreachableException extends IntegrationProbeException {

    public IntegrationProbeUnreachableException(String message) {
        super(message);
    }

    public IntegrationProbeUnreachableException(String message, Throwable cause) {
        super(message, cause);
    }
}
