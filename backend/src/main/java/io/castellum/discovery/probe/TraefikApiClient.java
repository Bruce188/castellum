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
 * Structural READ-ONLY wrapper for the Traefik API.
 *
 * <p><b>READ-ONLY invariant:</b> this class issues ONLY HTTP GET requests via hardcoded paths.
 * No verb/body methods are exposed. All public methods start with {@code get}.
 *
 * <p>Reuses {@link DockerEngineApiClient.HttpGetter} as the transport seam and the same
 * 16 MB capped-drain body pattern from {@link DockerEngineApiClient}.
 *
 * <p>Exposed endpoints:
 * <ul>
 *   <li>{@code GET /api/http/routers} — list Traefik HTTP routers</li>
 *   <li>{@code GET /api/http/services} — list Traefik HTTP services</li>
 *   <li>{@code GET /api/overview} — Traefik overview (fingerprint surface)</li>
 * </ul>
 */
@Component
public class TraefikApiClient {

    private static final Logger log = LoggerFactory.getLogger(TraefikApiClient.class);

    /** Maximum response body size: 16 MB. Bodies larger than this are rejected. */
    static final long MAX_BODY_BYTES = DockerEngineApiClient.MAX_BODY_BYTES;

    private final DockerEngineApiClient.HttpGetter getter;

    /**
     * Test seam constructor — caller supplies transport.
     */
    public TraefikApiClient(DockerEngineApiClient.HttpGetter getter) {
        this.getter = getter;
    }

    /**
     * Spring-managed constructor. Reads timeouts from config.
     */
    @org.springframework.beans.factory.annotation.Autowired
    public TraefikApiClient(
            @org.springframework.beans.factory.annotation.Value(
                "${castellum.docker.probe.connect-timeout-ms:2000}") int connectTimeoutMs,
            @org.springframework.beans.factory.annotation.Value(
                "${castellum.docker.probe.read-timeout-ms:5000}") int readTimeoutMs) {
        this(buildDefaultGetter(Duration.ofMillis(connectTimeoutMs), Duration.ofMillis(readTimeoutMs)));
    }

    /**
     * GET /api/http/routers — list Traefik HTTP routers.
     *
     * @param host target host
     * @param port Traefik API port (typically 8080)
     * @return JSON body, or empty on failure
     */
    public Optional<String> getRouters(String host, int port) {
        return getter.get(buildUri(host, port, "/api/http/routers"));
    }

    /**
     * GET /api/http/services — list Traefik HTTP services.
     *
     * @param host target host
     * @param port Traefik API port
     * @return JSON body, or empty on failure
     */
    public Optional<String> getServices(String host, int port) {
        return getter.get(buildUri(host, port, "/api/http/services"));
    }

    /**
     * GET /api/overview — Traefik dashboard overview (used for fingerprinting).
     *
     * @param host target host
     * @param port Traefik API port
     * @return JSON body, or empty on failure
     */
    public Optional<String> getOverview(String host, int port) {
        return getter.get(buildUri(host, port, "/api/overview"));
    }

    // ---- Private helpers ----

    private static URI buildUri(String host, int port, String path) {
        return URI.create("http://" + host + ":" + port + path);
    }

    static DockerEngineApiClient.HttpGetter buildDefaultGetter(Duration connectTimeout,
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
                if (status < 200 || status >= 300) {
                    log.debug("Traefik API {} returned HTTP {} — treating as empty", uri, status);
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
                            log.warn("Traefik API {} response body exceeds {} bytes — rejecting",
                                uri, MAX_BODY_BYTES);
                            return Optional.empty();
                        }
                        baos.write(buf, 0, read);
                    }
                    return Optional.of(baos.toString(java.nio.charset.StandardCharsets.UTF_8));
                }
            } catch (ConnectException | HttpTimeoutException e) {
                log.debug("Traefik API {} unreachable: {}", uri, e.getMessage());
                return Optional.empty();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Optional.empty();
            } catch (IOException e) {
                log.debug("Traefik API {} IO error: {}", uri, e.getMessage());
                return Optional.empty();
            }
        };
    }
}
