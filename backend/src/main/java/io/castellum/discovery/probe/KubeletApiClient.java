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
 * Structural READ-ONLY wrapper for the Kubernetes kubelet read-only port ({@code :10255}).
 *
 * <p><b>READ-ONLY invariant:</b> this class issues ONLY HTTP GET requests against the single
 * hardcoded path for the kubelet read-only API:
 * <ul>
 *   <li>{@code GET /pods} — list all pods running on this node (unauthenticated read-only port)</li>
 * </ul>
 *
 * <p>No verb, body, or free-form-path method is exposed. Every public method name begins with
 * {@code get}. (R4 reflection surface invariant.)
 *
 * <p><b>Port :10255 scheme:</b> the kubelet read-only port historically uses HTTP (not HTTPS) —
 * it is an intentionally unauthenticated, read-only port provided for monitoring tools. This
 * client uses {@code http://host:10255/pods}. Some newer Kubernetes installations disable the
 * read-only port entirely; in that case the connection is refused and the getter returns empty.
 *
 * <p><b>401/403 back-off:</b> non-2xx → {@link Optional#empty()} on the first send. No retry. (R3)
 */
@Component
public class KubeletApiClient {

    private static final Logger log = LoggerFactory.getLogger(KubeletApiClient.class);

    /** Maximum response body size: 16 MB (mirrors DockerEngineApiClient). */
    static final long MAX_BODY_BYTES = 16L * 1024 * 1024;

    /** Functional transport seam — same contract as DockerEngineApiClient.HttpGetter. */
    @FunctionalInterface
    public interface HttpGetter {
        Optional<String> get(URI uri);
    }

    private final HttpGetter getter;

    /** Test-seam constructor — caller supplies the transport. */
    public KubeletApiClient(HttpGetter getter) {
        this.getter = getter;
    }

    /** Spring-managed constructor — builds a default HTTP getter with timeouts. */
    @org.springframework.beans.factory.annotation.Autowired
    public KubeletApiClient(
            @Value("${castellum.docker.probe.connect-timeout-ms:2000}") int connectTimeoutMs,
            @Value("${castellum.docker.probe.read-timeout-ms:5000}") int readTimeoutMs) {
        this(buildDefaultGetter(Duration.ofMillis(connectTimeoutMs), Duration.ofMillis(readTimeoutMs)));
    }

    // ---- Public GET-only methods (hardcoded paths, READ-ONLY invariant) ----

    /**
     * GET /pods — list pods running on this kubelet node (read-only port, unauthenticated).
     *
     * <p>A 401/403 or connection refused → {@link Optional#empty()} on the first send. No retry. (R3)
     * The kubelet read-only port ({@code :10255}) is historically HTTP; this method uses
     * {@code http://host:port/pods}.
     *
     * @param host the kubelet host
     * @param port the kubelet read-only port (typically 10255)
     * @return the PodList JSON body, or empty on failure
     */
    public Optional<String> getPods(String host, int port) {
        return getter.get(buildUri(host, port, "/pods"));
    }

    // ---- Private helpers ----

    private static URI buildUri(String host, int port, String path) {
        // Kubelet read-only port :10255 is historically HTTP (unauthenticated, monitoring-only)
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
                    log.debug("KubeletApiClient {} returned HTTP {} — treating as empty (no retry)", uri, status);
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
                            log.warn("KubeletApiClient {} response exceeds {} bytes — rejecting", uri, MAX_BODY_BYTES);
                            return Optional.empty();
                        }
                        baos.write(buf, 0, read);
                    }
                    return Optional.of(baos.toString(java.nio.charset.StandardCharsets.UTF_8));
                }
            } catch (ConnectException | HttpTimeoutException e) {
                log.debug("KubeletApiClient {} unreachable: {}", uri, e.getMessage());
                return Optional.empty();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Optional.empty();
            } catch (IOException e) {
                String msg = e.getMessage();
                if (msg != null && (msg.contains("Connection refused") || msg.contains("refused"))) {
                    log.debug("KubeletApiClient {} connection refused", uri);
                } else {
                    log.debug("KubeletApiClient {} IO error: {}", uri, msg);
                }
                return Optional.empty();
            }
        };
    }
}
