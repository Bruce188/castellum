package io.castellum.ot;

/** Thrown when the requested protocol has not yet been wired in the fingerprint service. */
public final class OtProbeNotImplementedException extends OtProbeException {

    public OtProbeNotImplementedException(String message) {
        super(message);
    }

    public OtProbeNotImplementedException(String message, Throwable cause) {
        super(message, cause);
    }
}
