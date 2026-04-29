package io.castellum.risk;

import io.castellum.audit.AuditService;
import io.castellum.risk.dto.KevFeedDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

@Service
public class KevIngestionService {
    private static final Logger log = LoggerFactory.getLogger(KevIngestionService.class);
    private final KevClient client;
    private final KevUpsertService upserter;
    private final AuditService audit;

    public KevIngestionService(KevClient client, KevUpsertService upserter, AuditService audit) {
        this.client = client;
        this.upserter = upserter;
        this.audit = audit;
    }

    public KevIngestSummary ingest() throws IOException {
        var started = Instant.now();
        int entries = 0;
        int errors = 0;
        log.info("KEV ingest started");
        KevFeedDto feed = client.fetch();
        for (var dto : feed.vulnerabilities()) {
            try { upserter.upsert(dto, started); entries++; }
            catch (Exception e) {
                errors++;
                log.warn("KEV upsert failed for {}: {}", dto.cveId(), e.toString());
            }
        }
        var duration = Duration.between(started, Instant.now());
        audit.recordEvent("risk-feeds", "KEV_INGEST", "kev", feed.catalogVersion(),
            Map.of("entriesIngested", entries, "errors", errors, "catalogVersion", feed.catalogVersion()));
        log.info("KEV ingest complete: entries={} errors={} catalogVersion={} duration={}ms",
            entries, errors, feed.catalogVersion(), duration.toMillis());
        return new KevIngestSummary(entries, errors, feed.catalogVersion(), duration);
    }
}
