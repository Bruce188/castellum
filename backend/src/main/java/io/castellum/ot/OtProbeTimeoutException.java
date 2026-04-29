package io.castellum.ot;

/** Thrown when the OT probe connects successfully but the response does not arrive within the timeout. */
public final class OtProbeTimeoutException extends OtProbeException {

    public OtProbeTimeoutException(String message) {
        super(message);
    }

    public OtProbeTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }
}
