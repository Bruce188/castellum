package io.castellum.web;

import io.castellum.config.CacheConfig;
import io.castellum.config.CacheNames;
import io.castellum.cve.CveEnrichmentService;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.cve.FleetCveWindowService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Caching-behaviour tests for the page-independent fleet-sort window. The window scan
 * ({@code networkServiceRepository.findAll()} → match → bounded DB query → enrich → sort) is
 * page-independent; {@code @Cacheable(CVE_FLEET_WINDOW, key=(minScore,deviceId,sort))} must
 * collapse repeated calls (i.e. successive page requests of one sorted query) to a single scan,
 * and each scan/feed-sync eviction must force a recompute.
 *
 * <p>Mirrors {@link CveAffectedCacheTest}: loads only the real {@link CacheConfig}, the real
 * {@link FleetCveWindowService} (so its {@code @Cacheable} proxy is active), and the real
 * {@link RiskCacheEvictor}, with collaborators mocked. Boots on H2; does not trigger
 * DockerHostProbeService.
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {CacheConfig.class, FleetCveWindowService.class, RiskCacheEvictor.class})
class FleetCveWindowCacheTest {

    @Autowired FleetCveWindowService windowService;
    @Autowired RiskCacheEvictor riskCacheEvictor;
    @Autowired CacheManager cacheManager;

    @MockBean NetworkServiceRepository networkServiceRepository;
    @MockBean CveMatcher cveMatcher;
    @MockBean CveRepository cveRepository;
    @MockBean CveEnrichmentService enrichmentService;

    @BeforeEach
    void setUp() {
        for (String name : cacheManager.getCacheNames()) {
            Cache c = cacheManager.getCache(name);
            if (c != null) c.clear();
        }
        // Empty fleet → window short-circuits right after the findAll() scan; findAll() is the
        // page-independent cost the cache must short-circuit across successive page requests.
        when(networkServiceRepository.findAll()).thenReturn(List.of());
    }

    @Test
    void cveFleetWindowCacheIsRegistered() {
        assertThat(cacheManager.getCacheNames()).contains(CacheNames.CVE_FLEET_WINDOW);
    }

    @Test
    void secondCallSameQuery_servedFromCache_doesNotReScan() {
        windowService.window(null, null, "composite", Criticality.MEDIUM);
        windowService.window(null, null, "composite", Criticality.MEDIUM);

        // The fleet scan runs once — the second (e.g. next-page) call hit the window cache.
        verify(networkServiceRepository, times(1)).findAll();
    }

    @Test
    void onScanComplete_evictsWindow_forcesReScan() {
        windowService.window(null, null, "composite", Criticality.MEDIUM);
        riskCacheEvictor.onScanComplete();
        windowService.window(null, null, "composite", Criticality.MEDIUM);

        verify(networkServiceRepository, times(2)).findAll();
    }

    @Test
    void onFeedSyncComplete_evictsWindow_forcesReScan() {
        windowService.window(null, null, "composite", Criticality.MEDIUM);
        riskCacheEvictor.onFeedSyncComplete();
        windowService.window(null, null, "composite", Criticality.MEDIUM);

        verify(networkServiceRepository, times(2)).findAll();
    }
}
