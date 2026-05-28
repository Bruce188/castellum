package io.castellum.threatintel;

/** Thrown when the integration probe connects successfully but the response does not arrive within the timeout. */
public final class IntegrationProbeTimeoutException extends IntegrationProbeException {

    public IntegrationProbeTimeoutException(String message) {
        super(message);
    }

    public IntegrationProbeTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }
}
