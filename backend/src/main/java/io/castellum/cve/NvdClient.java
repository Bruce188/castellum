package io.castellum.cve;

import io.castellum.cve.dto.NvdCveResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

@Service
public class NvdClient {

    private static final Logger log = LoggerFactory.getLogger(NvdClient.class);
    private static final DateTimeFormatter NVD_TS =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS").withZone(ZoneOffset.UTC);
    private static final int MAX_ATTEMPTS = 3;

    private final RestClient client;
    private final long intervalMillis;
    private final Object lock = new Object();
    private long lastCallAt = 0L;

    public NvdClient(RestClient.Builder builder,
                     @Value("${castellum.nvd.base-url}") String baseUrl,
                     @Value("${castellum.nvd.api-key:}") String apiKey,
                     @Value("${castellum.nvd.request-interval-millis:6000}") long intervalMillis) {
        RestClient.Builder b = builder.baseUrl(baseUrl);
        if (apiKey != null && !apiKey.isBlank()) {
            b = b.defaultHeader("apiKey", apiKey);
        }
        this.client = b.build();
        this.intervalMillis = intervalMillis;
    }

    public NvdCveResponse fetchPage(Instant startMod, Instant endMod, int startIndex, int resultsPerPage) throws IOException {
        IOException lastError = null;
        long backoff = intervalMillis;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            sleepUntilNextSlot();
            try {
                return client.get()
                    .uri(uriBuilder -> uriBuilder
                        .queryParam("lastModStartDate", NVD_TS.format(startMod))
                        .queryParam("lastModEndDate", NVD_TS.format(endMod))
                        .queryParam("startIndex", startIndex)
                        .queryParam("resultsPerPage", resultsPerPage)
                        .build())
                    .retrieve()
                    .body(NvdCveResponse.class);
            } catch (HttpClientErrorException.Forbidden | HttpServerErrorException.ServiceUnavailable e) {
                log.warn("NVD transient error on attempt {}/{}: {}", attempt, MAX_ATTEMPTS, e.getStatusCode());
                lastError = new IOException("NVD transient error: " + e.getStatusCode(), e);
            } catch (ResourceAccessException e) {
                log.warn("NVD I/O error on attempt {}/{}: {}", attempt, MAX_ATTEMPTS, e.getMessage());
                lastError = new IOException("NVD I/O error", e);
            }
            if (attempt < MAX_ATTEMPTS) {
                try {
                    Thread.sleep(backoff);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted during NVD backoff", ie);
                }
                backoff *= 2;
            }
        }
        throw lastError != null ? lastError : new IOException("NVD fetch failed");
    }

    private void sleepUntilNextSlot() throws IOException {
        synchronized (lock) {
            long now = System.currentTimeMillis();
            long sleepFor = Math.max(0L, intervalMillis - (now - lastCallAt));
            if (sleepFor > 0) {
                try {
                    Thread.sleep(sleepFor);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted during NVD rate-limit sleep", ie);
                }
            }
            lastCallAt = System.currentTimeMillis();
        }
    }
}
