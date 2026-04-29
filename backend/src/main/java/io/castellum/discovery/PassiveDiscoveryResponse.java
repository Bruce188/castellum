package io.castellum.discovery;

import java.util.List;
import java.util.Map;

public record PassiveDiscoveryResponse(
    int discovered,
    List<Long> deviceIds,
    Map<DiscoverySource, Integer> perSourceCount
) {}
