package io.castellum.ot;

/** Thrown when the OT probe cannot connect to the target (connection refused, host unreachable). */
public final class OtProbeUnreachableException extends OtProbeException {

    public OtProbeUnreachableException(String message) {
        super(message);
    }

    public OtProbeUnreachableException(String message, Throwable cause) {
        super(message, cause);
    }
}
