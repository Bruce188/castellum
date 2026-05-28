package io.castellum.threatintel;

/**
 * Base class for all integration-probe exceptions.
 *
 * <p>Permitted subtypes:
 * <ul>
 *   <li>{@link IntegrationProbeUnreachableException} — target unreachable / connection refused</li>
 *   <li>{@link IntegrationProbeTimeoutException} — connect/read timeout</li>
 * </ul>
 */
public class IntegrationProbeException extends RuntimeException {

    public IntegrationProbeException(String message) {
        super(message);
    }

    public IntegrationProbeException(String message, Throwable cause) {
        super(message, cause);
    }
}
