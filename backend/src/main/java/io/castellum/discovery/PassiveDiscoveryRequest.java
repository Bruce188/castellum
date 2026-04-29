package io.castellum.discovery;

import java.util.List;

/**
 * Request for a passive discovery sweep. Annotations are relaxed here so that
 * the controller can apply defaults before validation occurs in the service.
 * See {@link io.castellum.web.PassiveScanController} for the normalization logic.
 */
public record PassiveDiscoveryRequest(
    String iface,
    int durationSeconds,
    List<DiscoverySource> sources
) {}
