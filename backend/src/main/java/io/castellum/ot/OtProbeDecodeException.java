package io.castellum.ot;

/** Thrown when the OT probe receives a response that fails protocol-level decode. */
public final class OtProbeDecodeException extends OtProbeException {

    public OtProbeDecodeException(String message) {
        super(message);
    }

    public OtProbeDecodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
