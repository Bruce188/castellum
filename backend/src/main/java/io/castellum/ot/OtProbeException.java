package io.castellum.ot;

/**
 * Sealed base class for all OT-probe exceptions.
 *
 * <p>Permitted subtypes:
 * <ul>
 *   <li>{@link OtProbeUnreachableException} — target unreachable / connection refused</li>
 *   <li>{@link OtProbeTimeoutException} — read timeout after TCP connect succeeded</li>
 *   <li>{@link OtProbeDecodeException} — response failed protocol decode</li>
 *   <li>{@link OtProbeNotImplementedException} — protocol not yet wired in the service</li>
 * </ul>
 */
public sealed class OtProbeException extends RuntimeException
    permits OtProbeUnreachableException, OtProbeTimeoutException,
            OtProbeDecodeException, OtProbeNotImplementedException {

    public OtProbeException(String message) {
        super(message);
    }

    public OtProbeException(String message, Throwable cause) {
        super(message, cause);
    }
}
