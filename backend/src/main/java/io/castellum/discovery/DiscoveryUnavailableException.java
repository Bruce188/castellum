package io.castellum.discovery;

public class DiscoveryUnavailableException extends RuntimeException {
    public DiscoveryUnavailableException(String message) { super(message); }
    public DiscoveryUnavailableException(String message, Throwable cause) { super(message, cause); }
}
