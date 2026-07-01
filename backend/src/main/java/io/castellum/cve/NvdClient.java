package io.castellum.cve;

import io.castellum.cve.dto.NvdCveResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import java.io.IOException;
import java.net.http.HttpClient;
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
                     @Value("${castellum.nvd.request-interval-millis:6000}") long intervalMillis,
                     @Value("${castellum.nvd.pin-http1:true}") boolean pinHttp1) {
        RestClient.Builder b = builder.baseUrl(baseUrl);
        if (apiKey != null && !apiKey.isBlank()) {
            b = b.defaultHeader("apiKey", apiKey);
        }
        if (pinHttp1) {
            // NVD resets large HTTP/2 responses mid-stream (RST_STREAM), truncating the
            // multi-thousand-CVE pages a full backfill pulls — beyond what fetchPage()'s retry can
            // recover (dense post-2023 windows fail all 3 attempts). HTTP/1.1 has no stream resets,
            // so full pages complete. Disabled in slice tests that mock the transport.
            b = b.requestFactory(new JdkClientHttpRequestFactory(
                HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build()));
        }
        this.client = b.build();
        this.intervalMillis = intervalMillis;
    }

    public NvdCveResponse fetchPage(Instant start, Instant end, int startIndex, int resultsPerPage) throws IOException {
        return fetchPage(start, end, startIndex, resultsPerPage, false);
    }

    /**
     * @param byPublished when {@code true}, windows by publish date ({@code pubStartDate}/{@code pubEndDate})
     *                    instead of last-modified — used by the full backfill so modern CVEs aren't buried on
     *                    the last pages of NVD's single mass-re-modified lastModified window. NVD caps both
     *                    ranges at 120 days, same {@code yyyy-MM-dd'T'HH:mm:ss.SSS} format either way.
     */
    public NvdCveResponse fetchPage(Instant start, Instant end, int startIndex, int resultsPerPage, boolean byPublished) throws IOException {
        String startParam = byPublished ? "pubStartDate" : "lastModStartDate";
        String endParam = byPublished ? "pubEndDate" : "lastModEndDate";
        IOException lastError = null;
        long backoff = intervalMillis;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            sleepUntilNextSlot();
            try {
                return client.get()
                    .uri(uriBuilder -> uriBuilder
                        .queryParam(startParam, NVD_TS.format(start))
                        .queryParam(endParam, NVD_TS.format(end))
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
            } catch (RestClientException e) {
                // NVD truncates large HTTP/2 responses mid-stream (RST_STREAM), surfaced by .body()
                // as a base RestClientException ("Error while extracting response..."). Retry those;
                // let real HTTP-status errors (4xx/5xx) propagate unchanged.
                // ponytail: if mid-stream resets ever exceed MAX_ATTEMPTS, pin the RestClient to HTTP/1.1.
                if (e instanceof RestClientResponseException) {
                    throw e;
                }
                log.warn("NVD response truncated on attempt {}/{}: {}", attempt, MAX_ATTEMPTS, e.getMessage());
                lastError = new IOException("NVD response truncated", e);
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
