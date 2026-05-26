package io.castellum.cve;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;

@Component
public class NvdSyncRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(NvdSyncRunner.class);

    private final NvdSyncService syncService;

    public NvdSyncRunner(NvdSyncService syncService) {
        this.syncService = syncService;
    }

    @Override
    public void run(ApplicationArguments args) throws IOException {
        if (!args.containsOption("nvd-sync")) {
            return;
        }
        List<String> sinceVals = args.getOptionValues("since");
        List<String> untilVals = args.getOptionValues("until");
        Instant since;
        if (sinceVals == null || sinceVals.isEmpty()) {
            since = null;
        } else {
            try {
                since = Instant.parse(sinceVals.get(0));
            } catch (DateTimeParseException dtpe) {
                throw new IllegalArgumentException("Invalid --since value: " + sinceVals.get(0), dtpe);
            }
        }
        Instant until;
        if (untilVals == null || untilVals.isEmpty()) {
            until = Instant.now();
        } else {
            try {
                until = Instant.parse(untilVals.get(0));
            } catch (DateTimeParseException dtpe) {
                throw new IllegalArgumentException("Invalid --until value: " + untilVals.get(0), dtpe);
            }
        }

        try {
            NvdSyncService.SyncSummary summary;
            if (since != null) {
                log.info("Starting NVD bulk pull: since={}, until={}", since, until);
                summary = syncService.bulkPull(since, until);
            } else {
                log.info("Starting NVD incremental pull (cursor=MAX(last_modified))");
                summary = syncService.incrementalPull();
            }
            log.info("NVD sync complete: slices={}, pages={}, cves={}, matches={}",
                summary.slicesProcessed(), summary.pagesFetched(), summary.cvesUpserted(), summary.matchesUpserted());
        } catch (IOException e) {
            log.error("NVD sync failed: {}", e.getMessage(), e);
            throw e;
        }
    }
}
