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
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Structural READ-ONLY wrapper for the Kubernetes API server ({@code :6443}).
 *
 * <p><b>READ-ONLY invariant:</b> this class issues ONLY HTTP GET requests against strictly
 * hardcoded paths corresponding to the anonymous read-only public API surface:
 * <ul>
 *   <li>{@code GET /api/v1/pods} — list all pods (anonymous read; returns empty on 401/403)</li>
 *   <li>{@code GET /api/v1/namespaces} — list all namespaces</li>
 *   <li>{@code GET /api/v1/namespaces/{ns}/secrets} — list secrets in a namespace</li>
 * </ul>
 *
 * <p>No verb, body, or free-form-path method is exposed. Every public method name begins with
 * {@code get}. (R4 reflection surface invariant.)
 *
 * <p><b>401/403 back-off:</b> non-2xx responses → {@link Optional#empty()} on the first send.
 * No retry loop is attempted — the {@link DockerEngineApiClient.HttpGetter} single-send semantics
 * give clean back-off for free. Callers distinguish "reachable but 401" (finding-only, HIGH) from
 * "anonymous read succeeded" (CRITICAL) by the presence or absence of a parsed body. (R3)
 *
 * <p><b>TLS:</b> the k8s API server uses HTTPS with a self-signed certificate by default.
 * The transport uses a trust-all {@link SSLContext} confined to this client — identical to the
 * probe posture for other self-signed targets in the scan boundary. This is acceptable because
 * the probe is READ-ONLY against a scan-authorized IP; MITM interception would at worst yield
 * incorrect data, not credential theft (no credentials are sent).
 */
@Component
public class K8sApiClient {

    private static final Logger log = LoggerFactory.getLogger(K8sApiClient.class);

    /** Maximum response body size: 16 MB (mirrors DockerEngineApiClient). */
    static final long MAX_BODY_BYTES = 16L * 1024 * 1024;

    /** Functional transport seam — same contract as DockerEngineApiClient.HttpGetter. */
    @FunctionalInterface
    public interface HttpGetter {
        Optional<String> get(URI uri);
    }

    private final HttpGetter getter;

    /** Test-seam constructor — caller supplies the transport. */
    public K8sApiClient(HttpGetter getter) {
        this.getter = getter;
    }

    /** Spring-managed constructor — builds a default HTTPS getter with trust-all SSLContext. */
    @org.springframework.beans.factory.annotation.Autowired
    public K8sApiClient(
            @Value("${castellum.docker.probe.connect-timeout-ms:2000}") int connectTimeoutMs,
            @Value("${castellum.docker.probe.read-timeout-ms:5000}") int readTimeoutMs) {
        this(buildDefaultGetter(Duration.ofMillis(connectTimeoutMs), Duration.ofMillis(readTimeoutMs)));
    }

    // ---- Public GET-only methods (hardcoded paths, READ-ONLY invariant) ----

    /**
     * GET /api/v1/pods — list all pods anonymously.
     *
     * <p>A 401/403 yields {@link Optional#empty()} on the first send — no retry. (R3)
     *
     * @param host the k8s API server host
     * @param port the k8s API server port (typically 6443)
     * @return the PodList JSON body, or empty on failure / 401 / 403
     */
    public Optional<String> getPods(String host, int port) {
        return getter.get(buildUri(host, port, "/api/v1/pods"));
    }

    /**
     * GET /api/v1/namespaces — list all namespaces anonymously.
     *
     * @param host the k8s API server host
     * @param port the k8s API server port
     * @return the NamespaceList JSON body, or empty on failure / 401 / 403
     */
    public Optional<String> getNamespaces(String host, int port) {
        return getter.get(buildUri(host, port, "/api/v1/namespaces"));
    }

    /**
     * GET /api/v1/namespaces/{ns}/secrets — list secrets in the given namespace anonymously.
     *
     * <p>This is the CRITICAL-escalation read — if a secret body is returned by an unauthenticated
     * request, the finding severity escalates from HIGH to CRITICAL. (R3)
     *
     * @param host the k8s API server host
     * @param port the k8s API server port
     * @param ns   the target namespace (e.g. {@code "default"})
     * @return the SecretList JSON body, or empty on failure / 401 / 403
     */
    public Optional<String> getSecrets(String host, int port, String ns) {
        return getter.get(buildUri(host, port, "/api/v1/namespaces/" + ns + "/secrets"));
    }

    // ---- Private helpers ----

    private static URI buildUri(String host, int port, String path) {
        return URI.create("https://" + host + ":" + port + path);
    }

    /**
     * Build a single-send HTTPS getter with a trust-all SSLContext, capped body, and timeouts.
     *
     * <p>The trust-all context is confined to this client (probe-only, scan-authorized hosts).
     * Non-2xx → empty (single shot, no retry). Body capped at {@value #MAX_BODY_BYTES}.
     */
    private static HttpGetter buildDefaultGetter(Duration connectTimeout, Duration readTimeout) {
        HttpClient client;
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);
            client = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .sslContext(ctx)
                .build();
        } catch (Exception e) {
            log.warn("K8sApiClient: failed to build trust-all SSLContext, falling back to default: {}", e.getMessage());
            client = HttpClient.newBuilder().connectTimeout(connectTimeout).build();
        }
        final HttpClient finalClient = client;
        return uri -> {
            try {
                HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(readTimeout)
                    .GET()
                    .build();
                HttpResponse<InputStream> response =
                    finalClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
                int status = response.statusCode();
                if (status < 200 || status >= 300) {
                    log.debug("K8sApiClient {} returned HTTP {} — treating as empty (401/403 back-off, no retry)", uri, status);
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
                            log.warn("K8sApiClient {} response exceeds {} bytes — rejecting", uri, MAX_BODY_BYTES);
                            return Optional.empty();
                        }
                        baos.write(buf, 0, read);
                    }
                    return Optional.of(baos.toString(java.nio.charset.StandardCharsets.UTF_8));
                }
            } catch (ConnectException | HttpTimeoutException e) {
                log.debug("K8sApiClient {} unreachable: {}", uri, e.getMessage());
                return Optional.empty();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Optional.empty();
            } catch (IOException e) {
                String msg = e.getMessage();
                if (msg != null && (msg.contains("Connection refused") || msg.contains("refused"))) {
                    log.debug("K8sApiClient {} connection refused", uri);
                } else {
                    log.debug("K8sApiClient {} IO error: {}", uri, msg);
                }
                return Optional.empty();
            }
        };
    }
}
