package io.castellum.graph;

import io.castellum.risk.RiskScore;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Per-build cache of {@link io.castellum.risk.CompositeScorer} outputs keyed on
 * {@code (cveId, deviceId)}.
 *
 * <p>NOT thread-safe. One instance per {@link GraphBuilder#build()} call.
 * Prevents redundant EPSS + KEV repository reads when multiple same-subnet peers
 * route through the same target device + CVE pair.
 *
 * <p>Caffeine cache deferred per analysis-v5 OQ#8 default.
 */
final class CompositeScoreMemoizer {

    private final Map<String, RiskScore> cache = new HashMap<>();

    RiskScore computeIfAbsent(String cveId, long deviceId, Supplier<RiskScore> compute) {
        String key = cveId + "|" + deviceId;
        return cache.computeIfAbsent(key, k -> compute.get());
    }
}
