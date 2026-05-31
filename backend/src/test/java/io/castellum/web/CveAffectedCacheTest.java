package io.castellum.web;

import io.castellum.config.CacheConfig;
import io.castellum.config.CacheNames;
import io.castellum.cve.Cve;
import io.castellum.cve.CveEnrichmentService;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.cve.FleetCveWindowService;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.KevEntryRepository;
import io.castellum.risk.RiskCacheEvictor;
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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Caching-behaviour tests for the reverse affected-devices endpoint
 * ({@code GET /api/cve/{cveId}/devices}). The handler's full fleet scan
 * ({@code networkServiceRepository.findAll()} → per-service match) runs on every CVE detail
 * open; the {@code @Cacheable(CVE_AFFECTED, key = "#cveId")} added to it must collapse repeat
 * opens to a single scan, and each scan/feed-sync eviction must force a recompute.
 *
 * <p>Mirrors {@link io.castellum.risk.DeviceRiskCacheTest}: loads only the real
 * {@link CacheConfig} (so {@code @EnableCaching} wires the Caffeine {@link CacheManager}), the
 * real {@link CveController} (so its {@code @Cacheable} proxy is active), and the real
 * {@link RiskCacheEvictor} (so its {@code @CacheEvict} proxies fire), with collaborators mocked.
 * The handler is invoked directly — {@code @PreAuthorize} is inert without method-security in
 * this slice, which is fine here: this test asserts caching, not authorization (covered by
 * {@code CveControllerTest}).
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {CacheConfig.class, CveController.class, RiskCacheEvictor.class})
class CveAffectedCacheTest {

    private static final String CVE_ID = "CVE-2020-15778";

    @Autowired CveController cveController;
    @Autowired RiskCacheEvictor riskCacheEvictor;
    @Autowired CacheManager cacheManager;

    @MockBean CveRepository cveRepository;
    @MockBean CveMatcher cveMatcher;
    @MockBean NetworkServiceRepository networkServiceRepository;
    @MockBean CveEnrichmentService enrichmentService;
    @MockBean KevEntryRepository kevEntryRepository;
    @MockBean DeviceRepository deviceRepository;
    @MockBean FleetCveWindowService fleetWindowService;

    @BeforeEach
    void setUp() {
        for (String name : cacheManager.getCacheNames()) {
            Cache c = cacheManager.getCache(name);
            if (c != null) c.clear();
        }
        Cve cve = new Cve();
        cve.setCveId(CVE_ID);
        cve.setId(1L);
        when(cveRepository.findByCveId(CVE_ID)).thenReturn(Optional.of(cve));
        // Empty fleet → handler returns 200 + [] after the scan; the scan (findAll) is the
        // cost we are proving the cache short-circuits.
        when(networkServiceRepository.findAll()).thenReturn(List.of());
    }

    @Test
    void cveAffectedCacheIsRegistered() {
        assertThat(cacheManager.getCacheNames()).contains(CacheNames.CVE_AFFECTED);
    }

    @Test
    void secondIdenticalCall_servedFromCache_doesNotReScanFleet() {
        cveController.getAffectedDevices(CVE_ID);
        cveController.getAffectedDevices(CVE_ID);

        // The reverse fleet scan must run exactly once — the second open is served from cache.
        verify(networkServiceRepository, times(1)).findAll();
    }

    @Test
    void resultIsCachedUnderCveAffectedKeyedByCveId() {
        cveController.getAffectedDevices(CVE_ID);

        Cache cache = cacheManager.getCache(CacheNames.CVE_AFFECTED);
        assertThat(cache).isNotNull();
        assertThat(cache.get(CVE_ID)).as("affected-devices must be cached under the cveId key").isNotNull();
    }

    @Test
    void onScanComplete_evictsCveAffected_forcesReScan() {
        cveController.getAffectedDevices(CVE_ID);
        riskCacheEvictor.onScanComplete();
        cveController.getAffectedDevices(CVE_ID);

        // Eviction cleared the entry, so the second open re-ran the fleet scan.
        verify(networkServiceRepository, times(2)).findAll();
    }

    @Test
    void onFeedSyncComplete_evictsCveAffected_forcesReScan() {
        cveController.getAffectedDevices(CVE_ID);
        riskCacheEvictor.onFeedSyncComplete();
        cveController.getAffectedDevices(CVE_ID);

        verify(networkServiceRepository, times(2)).findAll();
    }
}
