package io.castellum.threatintel.misp;

import io.castellum.threatintel.stix.StixBundle;
import io.castellum.threatintel.stix.StixInfrastructure;
import io.castellum.threatintel.stix.StixVulnerability;
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
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Service
public class MispClient {

    private static final Logger log = LoggerFactory.getLogger(MispClient.class);
    private static final int MAX_ATTEMPTS = 3;

    private final RestClient client;
    private final String distribution;
    private final String threatLevelId;
    private final long backoffBaseMillis;

    public MispClient(RestClient.Builder builder,
                      @Value("${castellum.misp.base-url:}") String baseUrl,
                      @Value("${castellum.misp.api-key:}") String apiKey,
                      @Value("${castellum.misp.distribution:0}") String distribution,
                      @Value("${castellum.misp.threat-level-id:2}") String threatLevelId,
                      @Value("${castellum.misp.backoff-base-millis:6000}") long backoffBaseMillis) {
        this.client = builder
            .baseUrl(baseUrl == null ? "" : baseUrl)
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .defaultHeader(HttpHeaders.AUTHORIZATION, apiKey == null ? "" : apiKey) // raw, no Bearer
            .build();
        this.distribution = distribution;
        this.threatLevelId = threatLevelId;
        this.backoffBaseMillis = backoffBaseMillis;
    }

    public MispPushResponse push(StixBundle bundle) throws IOException {
        MispEventEnvelope envelope = buildEnvelope(bundle);
        IOException lastError = null;
        long backoff = backoffBaseMillis;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                return client.post()
                    .uri("/events/add")
                    .body(envelope)
                    .retrieve()
                    .body(MispPushResponse.class);
            } catch (HttpClientErrorException.Unauthorized | HttpClientErrorException.Forbidden e) {
                throw new IOException("MISP auth failed: " + e.getStatusCode(), e);
            } catch (HttpServerErrorException e) {
                log.warn("MISP transient 5xx on attempt {}/{}: {}", attempt, MAX_ATTEMPTS, e.getStatusCode());
                lastError = new IOException("MISP server error: " + e.getStatusCode(), e);
            } catch (ResourceAccessException e) {
                log.warn("MISP I/O error on attempt {}/{}: {}", attempt, MAX_ATTEMPTS, e.getMessage());
                lastError = new IOException("MISP I/O error", e);
            }
            if (attempt < MAX_ATTEMPTS) {
                try {
                    Thread.sleep(backoff);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted during MISP backoff", ie);
                }
                backoff *= 2;
            }
        }
        throw lastError != null ? lastError : new IOException("MISP push failed");
    }

    private MispEventEnvelope buildEnvelope(StixBundle bundle) {
        Set<MispAttribute> attrs = new LinkedHashSet<>(); // dedup by equals on (type,value,category)
        for (var obj : bundle.objects()) {
            if (obj instanceof StixVulnerability v) {
                String cveId = v.externalReferences() != null && !v.externalReferences().isEmpty()
                    ? v.externalReferences().get(0).externalId() : v.name();
                attrs.add(new MispAttribute("vulnerability", "External analysis", cveId));
            } else if (obj instanceof StixInfrastructure i) {
                Object ip = i.extensions() != null && i.extensions().get("x_castellum") != null
                    ? i.extensions().get("x_castellum").get("ip_address") : null;
                if (ip != null) {
                    attrs.add(new MispAttribute("ip-dst", "Network activity", ip.toString()));
                }
            }
        }
        var event = new MispEventEnvelope.MispEvent(
            "Castellum threat-intel export " + Instant.now().toString(),
            distribution, threatLevelId, "1", List.copyOf(attrs));
        return new MispEventEnvelope(event);
    }
}
