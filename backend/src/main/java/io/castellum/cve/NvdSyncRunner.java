package io.castellum.cve;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.function.IntConsumer;

@Component
public class NvdSyncRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(NvdSyncRunner.class);

    private final NvdSyncService syncService;
    private final ConfigurableApplicationContext ctx;

    /**
     * Exit strategy invoked after a one-shot CLI sync completes. Defaults to a
     * clean Spring shutdown followed by {@link System#exit}. Tests inject a fake
     * consumer to assert the exit code WITHOUT killing the test JVM.
     */
    IntConsumer exitHandler;

    public NvdSyncRunner(NvdSyncService syncService, ConfigurableApplicationContext ctx) {
        this.syncService = syncService;
        this.ctx = ctx;
        this.exitHandler = code -> System.exit(SpringApplication.exit(ctx, () -> code));
    }

    @Override
    public void run(ApplicationArguments args) throws IOException {
        if (!args.containsOption("nvd-sync")) {
            return;
        }

        // --full forces an unconditional EPOCH→now full-corpus backfill,
        // bypassing the incremental findMaxLastModified path entirely.
        // Usage: --nvd-sync --full
        boolean full = args.containsOption("full");

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
            if (full) {
                // Explicit full-corpus backfill: EPOCH→now, no incremental short-circuit.
                // Equivalent to: --since 1970-01-01T00:00:00Z --until <now>
                log.info("Starting NVD full-corpus backfill (EPOCH→now, bypasses incremental cursor)");
                summary = syncService.fullBackfillPull();
            } else if (since != null) {
                log.info("Starting NVD bulk pull: since={}, until={}", since, until);
                summary = syncService.bulkPull(since, until);
            } else {
                log.info("Starting NVD incremental pull (cursor=MAX(last_modified))");
                summary = syncService.incrementalPull();
            }
            log.info("NVD sync complete: slices={}, pages={}, cves={}, matches={}",
                summary.slicesProcessed(), summary.pagesFetched(), summary.cvesUpserted(), summary.matchesUpserted());
            exitHandler.accept(0);
        } catch (IOException e) {
            log.error("NVD sync failed: {}", e.getMessage(), e);
            exitHandler.accept(1);
        }
    }
}
