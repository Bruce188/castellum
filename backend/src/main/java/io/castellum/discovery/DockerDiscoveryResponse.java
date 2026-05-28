package io.castellum.discovery;

import java.util.List;

/**
 * Summary of a single Docker discovery run.
 *
 * @param containers   number of running containers discovered and upserted
 * @param gateways     number of synthetic docker-network gateway devices upserted
 * @param updated      total devices upserted (containers + gateways) — the idempotent
 *                     "discovered/updated count" the trigger endpoint returns
 * @param deviceIds    ids of every upserted device (containers first, then gateways),
 *                     mirroring {@link PassiveDiscoveryResponse#deviceIds()}
 */
public record DockerDiscoveryResponse(
    int containers,
    int gateways,
    int updated,
    List<Long> deviceIds
) {
    public DockerDiscoveryResponse {
        deviceIds = deviceIds == null ? List.of() : List.copyOf(deviceIds);
    }
}
