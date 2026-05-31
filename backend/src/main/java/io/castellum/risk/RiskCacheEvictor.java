package io.castellum.risk;

import io.castellum.config.CacheNames;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Caching;
import org.springframework.stereotype.Component;

/**
 * Single, auditable home for the cache-eviction policy that keeps the four risk/CVE aggregate
 * caches consistent with the data they summarise. Each method names the <em>event</em> that
 * occurred; the annotations declare which caches that event invalidates.
 *
 * <p>Wiring it as a dedicated bean (rather than scattering {@code @CacheEvict} across the
 * controllers and ingestion services) keeps the "what invalidates what" matrix in one place and
 * ensures the {@code @CacheEvict} proxies actually fire — a {@code @CacheEvict} method invoked via
 * {@code this.} from inside the same bean is not intercepted.
 *
 * <table>
 *   <caption>Event → evicted caches</caption>
 *   <tr><th>Event</th><th>deviceRisk</th><th>topRisk</th><th>cveFleet</th><th>cveFleetWindow</th><th>feedsStatus</th></tr>
 *   <tr><td>scan complete</td><td>all</td><td>all</td><td>all</td><td>all</td><td>—</td></tr>
 *   <tr><td>criticality change</td><td>device</td><td>all</td><td>—</td><td>—</td><td>—</td></tr>
 *   <tr><td>feed-sync complete</td><td>all</td><td>all</td><td>all</td><td>all</td><td>all</td></tr>
 * </table>
 */
@Component
public class RiskCacheEvictor {

    /**
     * Scan finished — new services/CVEs may now match devices. Invalidates every per-device
     * score, the derived top-N ranking, the fleet CVE listing, and the page-independent
     * fleet-sort window (its scan→CVE matched set may have changed). {@code feedsStatus} is left
     * intact: a scan does not change NVD/EPSS/KEV corpus counts.
     */
    @Caching(evict = {
        @CacheEvict(cacheNames = CacheNames.DEVICE_RISK, allEntries = true),
        @CacheEvict(cacheNames = CacheNames.TOP_RISK, allEntries = true),
        @CacheEvict(cacheNames = CacheNames.CVE_FLEET, allEntries = true),
        @CacheEvict(cacheNames = CacheNames.CVE_FLEET_WINDOW, allEntries = true)
    })
    public void onScanComplete() {
        // No body — annotations perform the eviction.
    }

    /**
     * Device criticality (or any device field feeding the score) changed. Targets just that
     * device's risk entry, and clears the top-N ranking since the device's rank may have moved.
     * The fleet CVE listing is unaffected (criticality does not change which CVEs match).
     *
     * @param deviceId id of the updated device.
     */
    @Caching(evict = {
        @CacheEvict(cacheNames = CacheNames.DEVICE_RISK, key = "#deviceId"),
        @CacheEvict(cacheNames = CacheNames.TOP_RISK, allEntries = true)
    })
    public void onCriticalityChange(long deviceId) {
        // No body — annotations perform the eviction.
    }

    /**
     * Feed sync (NVD/EPSS/KEV) finished — new CVE scores, EPSS probabilities, KEV listings, and
     * corpus counts. Invalidates everything: per-device scores, the ranking, the fleet listing,
     * the page-independent fleet-sort window (its enrichment/ordering inputs changed), and the
     * feeds-status corpus snapshot (so {@code EmptyCorpusBanner} flips on the next poll).
     */
    @Caching(evict = {
        @CacheEvict(cacheNames = CacheNames.DEVICE_RISK, allEntries = true),
        @CacheEvict(cacheNames = CacheNames.TOP_RISK, allEntries = true),
        @CacheEvict(cacheNames = CacheNames.CVE_FLEET, allEntries = true),
        @CacheEvict(cacheNames = CacheNames.CVE_FLEET_WINDOW, allEntries = true),
        @CacheEvict(cacheNames = CacheNames.FEEDS_STATUS, allEntries = true)
    })
    public void onFeedSyncComplete() {
        // No body — annotations perform the eviction.
    }
}
