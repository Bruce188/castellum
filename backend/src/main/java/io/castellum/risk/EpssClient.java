package io.castellum.risk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.zip.GZIPInputStream;

@Service
public class EpssClient {
    private static final Logger log = LoggerFactory.getLogger(EpssClient.class);
    private static final long BACKOFF_BASE_MS = 6000L;
    private static final int MAX_ATTEMPTS = 3;

    private final String feedUrl;
    private final HttpClient httpClient;

    public EpssClient(@Value("${castellum.epss.feed-url}") String feedUrl, HttpClient httpClient) {
        this.feedUrl = feedUrl;
        this.httpClient = httpClient;
    }

    public BufferedReader fetchGunzippedReader() throws IOException {
        IOException last = null;
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(feedUrl))
                    .timeout(Duration.ofMinutes(2))
                    .GET().build();
                HttpResponse<InputStream> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofInputStream());
                int status = resp.statusCode();
                if (status >= 200 && status < 300) {
                    InputStream gunzipped = new GZIPInputStream(resp.body());
                    return new BufferedReader(new InputStreamReader(gunzipped, StandardCharsets.UTF_8));
                }
                if (status >= 500) {
                    last = new IOException("EPSS feed HTTP " + status);
                    log.warn("EPSS fetch attempt {} failed with HTTP {}; retrying", attempt + 1, status);
                } else {
                    throw new IOException("EPSS feed HTTP " + status + " (non-retriable)");
                }
            } catch (HttpTimeoutException e) {
                last = new IOException("EPSS feed timeout", e);
                log.warn("EPSS fetch attempt {} timed out; retrying", attempt + 1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("EPSS fetch interrupted", e);
            } catch (IOException e) {
                last = e;
                log.warn("EPSS fetch attempt {} failed: {}; retrying", attempt + 1, e.toString());
            }
            if (attempt < MAX_ATTEMPTS - 1) {
                try {
                    Thread.sleep(BACKOFF_BASE_MS * (1L << attempt));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("EPSS fetch interrupted during backoff", e);
                }
            }
        }
        throw new IOException("EPSS feed fetch failed after " + MAX_ATTEMPTS + " attempts", last);
    }
}
