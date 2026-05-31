package io.castellum.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.List;

/**
 * Caffeine-backed caching for the three pathologically slow aggregate endpoints.
 *
 * <p>Each cache is a named {@link CaffeineCache} with its own spec so eviction and
 * sizing can be tuned independently. Cache names live as constants in {@link CacheNames}
 * so {@code @Cacheable}/{@code @CacheEvict} call sites never hard-code string literals.
 *
 * <p>Why a {@link SimpleCacheManager} of explicit {@link CaffeineCache} beans rather than a
 * {@link org.springframework.cache.caffeine.CaffeineCacheManager} with a single global spec:
 * the caches have materially different freshness requirements (the feeds-status cache
 * must expire within one front-end poll cycle; the per-device risk cache can live far
 * longer). One spec cannot serve both, and per-cache registration on
 * {@code CaffeineCacheManager} is verbose and easy to get wrong. Explicit beans keep each
 * spec adjacent to the cache it governs.
 */
@Configuration
@EnableCaching
public class CacheConfig {

    /**
     * Per-device composite-risk cache. Hot path shared by {@code GET /api/risk/device/{id}},
     * {@code GET /api/risk/devices} (batch), and {@code GET /api/risk/top}. Keyed by deviceId.
     * Evicted on scan completion, device-criticality change, and feed-sync completion.
     */
    private static final Duration DEVICE_RISK_TTL = Duration.ofMinutes(10);
    private static final long DEVICE_RISK_MAX_SIZE = 5_000;

    /**
     * Top-N ranking cache. Keyed by the clamped {@code n}. Evicted on the same fleet-wide
     * events as the per-device cache. The ranking walks every device, so caching it spares
     * the whole-fleet recompute on every dashboard poll.
     */
    private static final Duration TOP_RISK_TTL = Duration.ofMinutes(10);
    private static final long TOP_RISK_MAX_SIZE = 200;

    /**
     * Fleet CVE-listing cache. Keyed by all query params (page, size, minScore, deviceId,
     * kevOnly, sort). Evicted on scan completion and feed-sync completion.
     */
    private static final Duration CVE_FLEET_TTL = Duration.ofMinutes(5);
    private static final long CVE_FLEET_MAX_SIZE = 1_000;

    /**
     * Page-independent fleet-sort window cache. Keyed by {@code (minScore, deviceId, sort)}
     * only (NOT page/size), so all pages of one sorted query share a single scan + enrich +
     * sort. Evicted on the same scan/feed-sync events as {@link CacheNames#CVE_FLEET}. The
     * key space is small — a handful of {@code minScore} floors × the supplied {@code deviceId}
     * (or none) × three sort modes — so a modest max-size bounds it comfortably while keeping
     * every active query's window resident.
     */
    private static final Duration CVE_FLEET_WINDOW_TTL = Duration.ofMinutes(5);
    private static final long CVE_FLEET_WINDOW_MAX_SIZE = 256;

    /**
     * Feeds-status cache. This endpoint drives {@code EmptyCorpusBanner}'s 10-second poll
     * that flips the UI from "feeds empty" to "feeds populated" once a sync finishes.
     *
     * <p><b>Eviction contract — do not weaken:</b> the TTL is deliberately SHORT (≤ the
     * poll interval) AND the cache is explicitly evicted on feed-sync completion
     * ({@code InitialSyncService} / {@code NvdSyncService}). Either mechanism alone keeps the
     * banner correct: the evict flips it on the very next poll after a sync; the short TTL is
     * a backstop for any sync path that forgets to evict. A long TTL here would strand the
     * banner showing a stale empty-corpus state for the full TTL window — never do that.
     */
    private static final Duration FEEDS_STATUS_TTL = Duration.ofSeconds(15);
    private static final long FEEDS_STATUS_MAX_SIZE = 4;

    @Bean
    public CacheManager cacheManager() {
        SimpleCacheManager manager = new SimpleCacheManager();
        manager.setCaches(List.of(
            caffeine(CacheNames.DEVICE_RISK, DEVICE_RISK_TTL, DEVICE_RISK_MAX_SIZE),
            caffeine(CacheNames.TOP_RISK, TOP_RISK_TTL, TOP_RISK_MAX_SIZE),
            caffeine(CacheNames.CVE_FLEET, CVE_FLEET_TTL, CVE_FLEET_MAX_SIZE),
            caffeine(CacheNames.CVE_FLEET_WINDOW, CVE_FLEET_WINDOW_TTL, CVE_FLEET_WINDOW_MAX_SIZE),
            caffeine(CacheNames.FEEDS_STATUS, FEEDS_STATUS_TTL, FEEDS_STATUS_MAX_SIZE)));
        return manager;
    }

    private static CaffeineCache caffeine(String name, Duration ttl, long maxSize) {
        return new CaffeineCache(name, Caffeine.newBuilder()
            .expireAfterWrite(ttl)
            .maximumSize(maxSize)
            .build());
    }
}
