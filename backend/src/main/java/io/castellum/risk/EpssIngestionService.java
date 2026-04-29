package io.castellum.risk;

import io.castellum.audit.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

@Service
public class EpssIngestionService {
    private static final Logger log = LoggerFactory.getLogger(EpssIngestionService.class);
    private final EpssClient client;
    private final EpssUpsertService upserter;
    private final AuditService audit;

    public EpssIngestionService(EpssClient client, EpssUpsertService upserter, AuditService audit) {
        this.client = client;
        this.upserter = upserter;
        this.audit = audit;
    }

    public EpssIngestSummary ingest() throws IOException {
        var started = Instant.now();
        int rows = 0;
        int errors = 0;
        log.info("EPSS ingest started");
        EpssCsvParser.ParseResult result;
        try (var reader = client.fetchGunzippedReader()) {
            result = EpssCsvParser.parse(reader);
        }
        for (var row : result.rows()) {
            try { upserter.upsert(row, result.scoreDate(), started); rows++; }
            catch (Exception e) {
                errors++;
                log.warn("EPSS upsert failed for {}: {}", row.cveId(), e.toString());
            }
        }
        var duration = Duration.between(started, Instant.now());
        audit.recordEvent("risk-feeds", "EPSS_INGEST", "epss", result.scoreDate().toString(),
            Map.of("rowsIngested", rows, "errors", errors, "scoreDate", result.scoreDate().toString()));
        log.info("EPSS ingest complete: rows={} errors={} scoreDate={} duration={}ms",
            rows, errors, result.scoreDate(), duration.toMillis());
        return new EpssIngestSummary(rows, errors, result.scoreDate(), duration);
    }
}
