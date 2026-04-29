package io.castellum.risk;

import io.castellum.risk.dto.KevFeedDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import java.io.IOException;

@Service
public class KevClient {
    private static final Logger log = LoggerFactory.getLogger(KevClient.class);
    private static final long BACKOFF_BASE_MS = 6000L;
    private static final int MAX_ATTEMPTS = 3;

    private final RestClient restClient;

    public KevClient(RestClient.Builder builder, @Value("${castellum.kev.feed-url}") String feedUrl) {
        this.restClient = builder.baseUrl(feedUrl).build();
    }

    public KevFeedDto fetch() throws IOException {
        Exception last = null;
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            try {
                return restClient.get().retrieve().body(KevFeedDto.class);
            } catch (HttpServerErrorException e) {
                last = e;
                log.warn("KEV fetch attempt {} failed with {}; retrying", attempt + 1, e.getStatusCode());
            } catch (ResourceAccessException e) {
                last = e;
                log.warn("KEV fetch attempt {} failed: {}; retrying", attempt + 1, e.toString());
            }
            if (attempt < MAX_ATTEMPTS - 1) {
                try {
                    Thread.sleep(BACKOFF_BASE_MS * (1L << attempt));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("KEV fetch interrupted", e);
                }
            }
        }
        throw new IOException("KEV feed fetch failed after " + MAX_ATTEMPTS + " attempts", last);
    }
}
