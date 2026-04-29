package io.castellum.risk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class RiskFeedScheduler {
    private static final Logger log = LoggerFactory.getLogger(RiskFeedScheduler.class);
    private final EpssIngestionService epss;
    private final KevIngestionService kev;

    public RiskFeedScheduler(EpssIngestionService epss, KevIngestionService kev) {
        this.epss = epss;
        this.kev = kev;
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
    }
}
