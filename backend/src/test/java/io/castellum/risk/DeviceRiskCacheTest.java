package io.castellum.risk;

import io.castellum.config.CacheConfig;
import io.castellum.config.CacheNames;
import io.castellum.cve.CveMatcher;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkServiceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Caching-behaviour tests for the per-device composite-risk hot path.
 *
 * <p>Loads only the real {@link CacheConfig} (so {@code @EnableCaching} wires the Caffeine
 * {@link CacheManager}), the real {@link DeviceRiskService} (so its {@code @Cacheable} proxy is
 * active), and the real {@link RiskCacheEvictor} (so its {@code @CacheEvict} proxies fire), with
 * the repositories mocked. This is the minimal context that can prove the cache actually
 * short-circuits repository work and that each eviction event forces a recompute.
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {CacheConfig.class, DeviceRiskService.class, RiskCacheEvictor.class})
class DeviceRiskCacheTest {

    @Autowired DeviceRiskService deviceRiskService;
    @Autowired RiskCacheEvictor riskCacheEvictor;
    @Autowired CacheManager cacheManager;

    @MockBean DeviceRepository deviceRepo;
    @MockBean NetworkServiceRepository networkServiceRepository;
    @MockBean CveMatcher cveMatcher;
    @MockBean EpssScoreRepository epssRepo;
    @MockBean KevEntryRepository kevRepo;

    @BeforeEach
    void clearCaches() {
        for (String name : cacheManager.getCacheNames()) {
            Cache c = cacheManager.getCache(name);
            if (c != null) c.clear();
        }
        Device d = new Device(1L, "10.0.0.1", "host-1", null, null, null, Criticality.MEDIUM);
        when(deviceRepo.findById(1L)).thenReturn(Optional.of(d));
        when(networkServiceRepository.findByDeviceId(1L)).thenReturn(List.of());
    }

    @Test
    void allFourNamedCachesAreRegistered() {
        assertThat(cacheManager.getCacheNames())
            .contains(CacheNames.DEVICE_RISK, CacheNames.TOP_RISK,
                      CacheNames.CVE_FLEET, CacheNames.FEEDS_STATUS);
    }

    @Test
    void secondIdenticalCall_doesNotReHitRepositories() {
        deviceRiskService.computeRisk(1L);
        deviceRiskService.computeRisk(1L);

        // The expensive lookups must run exactly once — the second call is served from cache.
        verify(deviceRepo, times(1)).findById(1L);
        verify(networkServiceRepository, times(1)).findByDeviceId(1L);
    }

    @Test
    void resultIsCachedUnderDeviceRiskCacheKeyedByDeviceId() {
        deviceRiskService.computeRisk(1L);

        Cache cache = cacheManager.getCache(CacheNames.DEVICE_RISK);
        assertThat(cache).isNotNull();
        // Keyed by deviceId per @Cacheable(key = "#deviceId").
        assertThat(cache.get(1L)).as("device 1's risk must be cached under key 1").isNotNull();
    }

    @Test
    void onScanComplete_evictsDeviceRisk_forcesRecompute() {
        deviceRiskService.computeRisk(1L);
        riskCacheEvictor.onScanComplete();
        deviceRiskService.computeRisk(1L);

        // Eviction cleared the entry, so the second compute re-hit the repositories.
        verify(deviceRepo, times(2)).findById(1L);
        verify(networkServiceRepository, times(2)).findByDeviceId(1L);
    }

    @Test
    void onCriticalityChange_evictsThatDevice_forcesRecompute() {
        deviceRiskService.computeRisk(1L);
        riskCacheEvictor.onCriticalityChange(1L);
        deviceRiskService.computeRisk(1L);

        verify(deviceRepo, times(2)).findById(1L);
        verify(networkServiceRepository, times(2)).findByDeviceId(1L);
    }

    @Test
    void onCriticalityChange_otherDevice_doesNotEvictUnrelatedEntry() {
        Device d2 = new Device(2L, "10.0.0.2", "host-2", null, null, null, Criticality.HIGH);
        when(deviceRepo.findById(2L)).thenReturn(Optional.of(d2));
        when(networkServiceRepository.findByDeviceId(2L)).thenReturn(List.of());

        deviceRiskService.computeRisk(1L);
        // Targeted evict of a DIFFERENT device must leave device 1's cache entry intact.
        riskCacheEvictor.onCriticalityChange(2L);
        deviceRiskService.computeRisk(1L);

        verify(deviceRepo, times(1)).findById(1L);
        verify(networkServiceRepository, times(1)).findByDeviceId(1L);
    }

    @Test
    void onFeedSyncComplete_evictsDeviceRisk_forcesRecompute() {
        deviceRiskService.computeRisk(1L);
        riskCacheEvictor.onFeedSyncComplete();
        deviceRiskService.computeRisk(1L);

        verify(deviceRepo, times(2)).findById(1L);
        verify(networkServiceRepository, times(2)).findByDeviceId(1L);
    }

    @Test
    void onFeedSyncComplete_evictsFeedsStatusCache() {
        Cache feeds = cacheManager.getCache(CacheNames.FEEDS_STATUS);
        assertThat(feeds).isNotNull();
        feeds.put("singleton", "stale-snapshot");

        riskCacheEvictor.onFeedSyncComplete();

        // The feeds-status snapshot must be cleared so EmptyCorpusBanner flips on the next poll.
        assertThat(feeds.get("singleton"))
            .as("feeds-status cache must be evicted on feed-sync completion")
            .isNull();
    }
}
