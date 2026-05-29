package io.castellum.discovery.probe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
 * Structural READ-ONLY wrapper for the Docker Engine API.
 *
 * <p><b>READ-ONLY invariant:</b> this class issues ONLY HTTP GET requests. It exposes no method
 * that accepts an HTTP verb, a request body, or a free-form path. The four public methods have
 * hardcoded paths corresponding exactly to the Docker Engine API endpoints this probe requires:
 * <ul>
 *   <li>{@code GET /networks} — list all networks</li>
 *   <li>{@code GET /networks/{id}} — inspect one network</li>
 *   <li>{@code GET /containers/json} — list running containers</li>
 *   <li>{@code GET /containers/{id}/json} — inspect one container</li>
 * </ul>
 *
 * <p>Transport is injected as {@link HttpGetter} so tests pass a lambda returning fixture JSON
 * without opening any real socket. The default constructor builds an {@link HttpClient}-backed
 * getter with connect and read timeouts.
 *
 * <p>Response bodies are capped at {@value #MAX_BODY_BYTES} bytes (16 MB). Responses beyond
 * this cap are rejected with an empty result — the scan continues on the next host.
 *
 * <p>Connection errors, timeouts, and TCP-refused responses return {@link Optional#empty()} so
 * the caller can treat them as a closed-port fast no-op.
 */
@Component
public class DockerEngineApiClient {

    private static final Logger log = LoggerFactory.getLogger(DockerEngineApiClient.class);

    /** Maximum response body size: 16 MB. Bodies larger than this are rejected. */
    static final long MAX_BODY_BYTES = 16L * 1024 * 1024;

    /**
     * Functional interface for the HTTP transport seam. Tests supply a lambda; production uses
     * {@link HttpClient}.
     */
    @FunctionalInterface
    public interface HttpGetter {
        /**
         * Perform an HTTP GET to the given URI.
         *
         * @param uri the target URI
         * @return the response body as a string, or empty on connection failure / timeout
         */
        Optional<String> get(URI uri);
    }

    private final HttpGetter getter;

    /**
     * Test seam constructor — caller supplies the transport.
     *
     * @param getter the HTTP transport implementation
     */
    public DockerEngineApiClient(HttpGetter getter) {
        this.getter = getter;
    }

    /**
     * Spring-managed constructor. Reads timeouts from {@code application.yml}.
     *
     * @param connectTimeoutMs connect timeout in milliseconds
     * @param readTimeoutMs    read timeout in milliseconds
     */
    @org.springframework.beans.factory.annotation.Autowired
    public DockerEngineApiClient(
            @Value("${castellum.docker.probe.connect-timeout-ms:2000}") int connectTimeoutMs,
            @Value("${castellum.docker.probe.read-timeout-ms:5000}") int readTimeoutMs) {
        this(buildDefaultGetter(Duration.ofMillis(connectTimeoutMs), Duration.ofMillis(readTimeoutMs)));
    }

    /**
     * No-arg fallback for contexts where config is not available.
     * Builds a getter with default 2 s connect / 5 s read timeouts.
     */
    public DockerEngineApiClient() {
        this(buildDefaultGetter(Duration.ofSeconds(2), Duration.ofSeconds(5)));
    }

    // ---- Public GET-only methods (hardcoded paths, READ-ONLY invariant) ----

    /**
     * GET /networks — list all networks.
     *
     * @param host the Docker daemon host
     * @param port the Docker daemon port (typically 2375)
     * @return the response body JSON, or empty on failure
     */
    public Optional<String> getNetworks(String host, int port) {
        return getter.get(buildUri(host, port, "/networks"));
    }

    /**
     * GET /networks/{id} — inspect one network.
     *
     * @param host the Docker daemon host
     * @param port the Docker daemon port
     * @param id   the network ID or name
     * @return the response body JSON, or empty on failure
     */
    public Optional<String> getNetwork(String host, int port, String id) {
        return getter.get(buildUri(host, port, "/networks/" + id));
    }

    /**
     * GET /containers/json — list running containers (summary form).
     *
     * @param host the Docker daemon host
     * @param port the Docker daemon port
     * @return the response body JSON, or empty on failure
     */
    public Optional<String> getContainers(String host, int port) {
        return getter.get(buildUri(host, port, "/containers/json"));
    }

    /**
     * GET /containers/{id}/json — inspect one container (full inspect form, same shape as
     * {@code docker inspect}).
     *
     * @param host the Docker daemon host
     * @param port the Docker daemon port
     * @param id   the container ID or name
     * @return the response body JSON, or empty on failure
     */
    public Optional<String> getContainerInspect(String host, int port, String id) {
        return getter.get(buildUri(host, port, "/containers/" + id + "/json"));
    }

    // ---- Private helpers ----

    private static URI buildUri(String host, int port, String path) {
        return URI.create("http://" + host + ":" + port + path);
    }

    private static HttpGetter buildDefaultGetter(Duration connectTimeout, Duration readTimeout) {
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
                    log.debug("Docker API {} returned HTTP {} — treating as empty", uri, status);
                    response.body().close();
                    return Optional.empty();
                }
                // Cap body at MAX_BODY_BYTES — mirror DockerCliClient.readCapped
                try (InputStream body = response.body()) {
                    byte[] buf = new byte[4096];
                    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                    long total = 0;
                    int read;
                    while ((read = body.read(buf)) != -1) {
                        total += read;
                        if (total > MAX_BODY_BYTES) {
                            log.warn("Docker API {} response body exceeds {} bytes — rejecting", uri, MAX_BODY_BYTES);
                            return Optional.empty();
                        }
                        baos.write(buf, 0, read);
                    }
                    return Optional.of(baos.toString(java.nio.charset.StandardCharsets.UTF_8));
                }
            } catch (ConnectException | HttpTimeoutException e) {
                log.debug("Docker API {} unreachable: {}", uri, e.getMessage());
                return Optional.empty();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Optional.empty();
            } catch (IOException e) {
                // Connection refused and other IO errors — treat as closed port
                String msg = e.getMessage();
                if (msg != null && (msg.contains("Connection refused") || msg.contains("refused"))) {
                    log.debug("Docker API {} connection refused", uri);
                } else {
                    log.debug("Docker API {} IO error: {}", uri, msg);
                }
                return Optional.empty();
            }
        };
    }
}
