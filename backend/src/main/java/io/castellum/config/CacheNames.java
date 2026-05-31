package io.castellum.config;

/**
 * Canonical cache-name constants. Referenced by {@link CacheConfig} (registration),
 * the {@code @Cacheable} producers, and every {@code @CacheEvict} trigger so the cache
 * name is never a bare string literal that could drift between definition and use.
 */
public final class CacheNames {

    /** Per-device composite risk ({@code DeviceRiskDto} + KEV count), keyed by deviceId. */
    public static final String DEVICE_RISK = "deviceRisk";

    /** Top-N at-risk device ranking, keyed by the clamped {@code n}. */
    public static final String TOP_RISK = "topRisk";

    /** Fleet CVE listing, keyed by the full query-param tuple. */
    public static final String CVE_FLEET = "cveFleet";

    /**
     * Page-independent fleet-sort window (scan + enrich + sort) for the
     * {@code sort=composite|kev|epss} path, keyed by {@code (minScore, deviceId, sort)}
     * so all pages of one query reuse a single computation. Evicted on the same
     * fleet/corpus events as {@link #CVE_FLEET}.
     */
    public static final String CVE_FLEET_WINDOW = "cveFleetWindow";

    /** Feed-corpus status (NVD/EPSS/KEV counts + freshness), single keyed entry. */
    public static final String FEEDS_STATUS = "feedsStatus";

    /** Affected-device list per CVE ({@code GET /api/cve/{cveId}/devices}), keyed by cveId. */
    public static final String CVE_AFFECTED = "cveAffected";

    private CacheNames() {
        throw new UnsupportedOperationException("constants holder");
    }
}
