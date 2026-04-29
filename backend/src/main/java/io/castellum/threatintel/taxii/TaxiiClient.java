package io.castellum.threatintel.taxii;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class TaxiiClient {

    private static final Logger log = LoggerFactory.getLogger(TaxiiClient.class);
    private static final MediaType TAXII_21 = MediaType.parseMediaType("application/taxii+json;version=2.1");
    private static final int MAX_ATTEMPTS = 3;

    private final RestClient client;
    private final String collectionId;
    private final long backoffBaseMillis;

    public TaxiiClient(RestClient.Builder builder,
                       @Value("${castellum.taxii.base-url:}") String baseUrl,
                       @Value("${castellum.taxii.collection-id:}") String collectionId,
                       @Value("${castellum.taxii.username:}") String username,
                       @Value("${castellum.taxii.password:}") String password,
                       @Value("${castellum.taxii.backoff-base-millis:6000}") long backoffBaseMillis) {
        String basic = "Basic " + Base64.getEncoder().encodeToString(
            (username + ":" + password).getBytes(StandardCharsets.UTF_8));
        this.client = builder
            .baseUrl(baseUrl == null ? "" : baseUrl)
            .defaultHeader(HttpHeaders.CONTENT_TYPE, TAXII_21.toString())
            .defaultHeader(HttpHeaders.ACCEPT, TAXII_21.toString())
            .defaultHeader(HttpHeaders.AUTHORIZATION, basic)
            .build();
        this.collectionId = collectionId;
        this.backoffBaseMillis = backoffBaseMillis;
    }

    public int push(String bundleJson) throws IOException {
        return push(bundleJson, this.collectionId);
    }

    public int push(String bundleJson, String collectionOverride) throws IOException {
        IOException lastError = null;
        long backoff = backoffBaseMillis;
        String collection = collectionOverride != null && !collectionOverride.isBlank()
            ? collectionOverride : this.collectionId;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                var response = client.post()
                    .uri("/collections/{id}/objects/", collection)
                    .body(bundleJson)
                    .retrieve()
                    .toBodilessEntity();
                return response.getStatusCode().value();
            } catch (HttpClientErrorException.Unauthorized | HttpClientErrorException.Forbidden e) {
                throw new IOException("TAXII auth failed: " + e.getStatusCode(), e);
            } catch (HttpServerErrorException e) {
                log.warn("TAXII transient 5xx on attempt {}/{}: {}", attempt, MAX_ATTEMPTS, e.getStatusCode());
                lastError = new IOException("TAXII server error: " + e.getStatusCode(), e);
            } catch (ResourceAccessException e) {
                log.warn("TAXII I/O error on attempt {}/{}: {}", attempt, MAX_ATTEMPTS, e.getMessage());
                lastError = new IOException("TAXII I/O error", e);
            }
            if (attempt < MAX_ATTEMPTS) {
                try {
                    Thread.sleep(backoff);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted during TAXII backoff", ie);
                }
                backoff *= 2;
            }
        }
        throw lastError != null ? lastError : new IOException("TAXII push failed");
    }
}
