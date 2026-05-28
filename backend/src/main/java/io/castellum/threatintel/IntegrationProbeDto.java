package io.castellum.threatintel;

/**
 * Request / response DTOs for the integration probe endpoint.
 */
public class IntegrationProbeDto {

    /** POST body: the URL (and optional collection ID) to probe. */
    public record ProbeRequest(String url, String collectionId) {}

    /** Probe outcome: whether the target was reachable, and a short detail string. */
    public record ProbeResult(boolean reachable, String detail) {}
}
