package io.castellum.risk;

import io.castellum.admin.InitialSyncService;
import io.castellum.cve.NvdSyncService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class RiskFeedScheduler {
    private static final Logger log = LoggerFactory.getLogger(RiskFeedScheduler.class);
    private final EpssIngestionService epss;
    private final KevIngestionService kev;
    private final NvdSyncService nvd;
    private final InitialSyncService initialSyncService;
    private final RiskCacheEvictor riskCacheEvictor;

    public RiskFeedScheduler(EpssIngestionService epss, KevIngestionService kev,
                              NvdSyncService nvd, InitialSyncService initialSyncService,
                              RiskCacheEvictor riskCacheEvictor) {
        this.epss = epss;
        this.kev = kev;
        this.nvd = nvd;
        this.initialSyncService = initialSyncService;
        this.riskCacheEvictor = riskCacheEvictor;
    }

    @Scheduled(cron = "${castellum.risk.refresh-cron:0 0 6 * * *}", zone = "UTC")
    public void runFeeds() {
        try {
            epss.ingest();
        } catch (Exception e) {
            log.error("EPSS ingest failed: {}", e.toString(), e);
        }
        try {
            kev.ingest();
        } catch (Exception e) {
            log.error("KEV ingest failed: {}", e.toString(), e);
        }
        try {
            if (initialSyncService.isInFlight()) {
                log.info("Scheduled NVD incremental pull skipped — manual sync in flight");
            } else {
                nvd.incrementalPull();
            }
        } catch (Exception e) {
            log.error("NVD incremental pull failed: {}", e.toString(), e);
        }
        // Scheduled refresh may have written new corpus rows — invalidate aggregate caches
        // (including feeds-status) so the next poll reflects the refreshed corpus.
        riskCacheEvictor.onFeedSyncComplete();
    }
}
