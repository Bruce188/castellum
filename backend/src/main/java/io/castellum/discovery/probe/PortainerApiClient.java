package io.castellum.discovery.probe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Optional;

/**
 * Structural READ-ONLY wrapper for the Portainer API.
 *
 * <p><b>READ-ONLY invariant:</b> this class issues ONLY HTTP GET requests. No login, no POST,
 * no authentication method. Portainer is DETECTED always (via /api/status) and EXTRACTED only
 * when no authentication is required — 401 responses surface as empty (R10).
 *
 * <p>All public methods start with {@code get}. No verb/body method is exposed.
 *
 * <p>Reuses {@link DockerEngineApiClient.HttpGetter} transport seam and 16 MB capped-drain.
 */
@Component
public class PortainerApiClient {

    private static final Logger log = LoggerFactory.getLogger(PortainerApiClient.class);

    /** Maximum response body size: 16 MB. */
    static final long MAX_BODY_BYTES = DockerEngineApiClient.MAX_BODY_BYTES;

    private final DockerEngineApiClient.HttpGetter getter;

    /**
     * Test seam constructor.
     */
    public PortainerApiClient(DockerEngineApiClient.HttpGetter getter) {
        this.getter = getter;
    }

    /**
     * Spring-managed constructor.
     */
    @org.springframework.beans.factory.annotation.Autowired
    public PortainerApiClient(
            @org.springframework.beans.factory.annotation.Value(
                "${castellum.docker.probe.connect-timeout-ms:2000}") int connectTimeoutMs,
            @org.springframework.beans.factory.annotation.Value(
                "${castellum.docker.probe.read-timeout-ms:5000}") int readTimeoutMs) {
        this(buildDefaultGetter(
            Duration.ofMillis(connectTimeoutMs),
            Duration.ofMillis(readTimeoutMs)));
    }

    /**
     * GET /api/status — detect Portainer presence.
     *
     * <p>Returns the status JSON if Portainer is present (any 2xx). Returns empty on failure
     * or non-2xx (including 401 — auth required but we don't forge creds).
     *
     * @param host target host
     * @param port Portainer port (typically 9000 or 9443)
     * @return JSON status body, or empty if not a Portainer instance
     */
    public Optional<String> getStatus(String host, int port) {
        return getter.get(buildUri(host, port, "/api/status"));
    }

    /**
     * GET /api/endpoints — extract Portainer-managed endpoints (R10).
     *
     * <p>Returns endpoint list only when no authentication is required. A 401 response (auth
     * required) is surfaced as empty — we do NOT forge credentials or attempt login (R10).
     *
     * @param host target host
     * @param port Portainer port
     * @return JSON endpoints array, or empty if auth required or failure
     */
    public Optional<String> getEndpoints(String host, int port) {
        return getter.get(buildUri(host, port, "/api/endpoints"));
    }

    // ---- Private helpers ----

    private static URI buildUri(String host, int port, String path) {
        return URI.create("http://" + host + ":" + port + path);
    }

    private static DockerEngineApiClient.HttpGetter buildDefaultGetter(Duration connectTimeout,
                                                                       Duration readTimeout) {
        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(connectTimeout)
            .build();
        return uri -> {
            try {
                HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(readTimeout)
                    .GET()
                    .build();
                HttpResponse<InputStream> response =
                    client.send(request, HttpResponse.BodyHandlers.ofInputStream());
                int status = response.statusCode();
                if (status == 401) {
                    // Auth required — R10: do not forge creds, return empty
                    log.debug("Portainer API {} returned 401 — no-auth extraction skipped", uri);
                    response.body().close();
                    return Optional.empty();
                }
                if (status < 200 || status >= 300) {
                    log.debug("Portainer API {} returned HTTP {} — treating as empty", uri, status);
                    response.body().close();
                    return Optional.empty();
                }
                try (InputStream body = response.body()) {
                    byte[] buf = new byte[4096];
                    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                    long total = 0;
                    int read;
                    while ((read = body.read(buf)) != -1) {
                        total += read;
                        if (total > MAX_BODY_BYTES) {
                            log.warn("Portainer API {} response body exceeds {} bytes — rejecting",
                                uri, MAX_BODY_BYTES);
                            return Optional.empty();
                        }
                        baos.write(buf, 0, read);
                    }
                    return Optional.of(baos.toString(java.nio.charset.StandardCharsets.UTF_8));
                }
            } catch (ConnectException | HttpTimeoutException e) {
                log.debug("Portainer API {} unreachable: {}", uri, e.getMessage());
                return Optional.empty();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Optional.empty();
            } catch (IOException e) {
                log.debug("Portainer API {} IO error: {}", uri, e.getMessage());
                return Optional.empty();
            }
        };
    }
}
