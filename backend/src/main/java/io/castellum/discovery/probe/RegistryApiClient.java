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
import java.util.regex.Pattern;

/**
 * Structural READ-ONLY wrapper for the Docker Registry v2 API ({@code :5000}).
 *
 * <p><b>READ-ONLY invariant:</b> this class issues ONLY HTTP GET requests against strictly
 * hardcoded paths:
 * <ul>
 *   <li>{@code GET /v2/_catalog} — list repository names</li>
 *   <li>{@code GET /v2/{name}/tags/list} — list tags for one repository</li>
 * </ul>
 *
 * <p>No verb, body, or free-form-path method is exposed. Every public method name begins with
 * {@code get}. (R4 reflection surface invariant.)
 *
 * <p><b>Authentication:</b> Docker Registry v2 returns 401 when the catalog endpoint requires
 * authentication. Non-2xx → {@link Optional#empty()} on the first send — no retry, no credential
 * extraction. The MEDIUM finding is only raised when the catalog answers without authentication.
 * A 401 response yields empty with no extraction. (R3)
 *
 * <p><b>Scheme:</b> the default Docker registry listens on HTTP. HTTPS registries may exist but
 * we probe port 5000 via HTTP (unauthenticated registries on the default port are always HTTP).
 */
@Component
public class RegistryApiClient {

    private static final Logger log = LoggerFactory.getLogger(RegistryApiClient.class);

    /**
     * Security: Docker repository-name grammar validation pattern.
     *
     * Accepts: lowercase path-components of [a-z0-9] runs joined by single '.', '_', '-', or '/'
     * separators (e.g. "nginx", "library/nginx").
     * Rejects: '@', '..', '?', '#', '%', whitespace, CRLF, uppercase, leading/trailing separator,
     * or names exceeding 255 chars — forecloses host-redirect, path traversal, query/fragment
     * smuggling, and CRLF injection via untrusted registry-supplied names.
     */
    private static final Pattern REPO_NAME_PATTERN =
            Pattern.compile("^[a-z0-9]+([._\\-/][a-z0-9]+)*$");

    /** Maximum repository name length per Docker spec. */
    private static final int MAX_REPO_NAME_LENGTH = 255;

    /** Maximum response body size: 16 MB (mirrors DockerEngineApiClient). */
    static final long MAX_BODY_BYTES = 16L * 1024 * 1024;

    /** Functional transport seam. */
    @FunctionalInterface
    public interface HttpGetter {
        Optional<String> get(URI uri);
    }

    private final HttpGetter getter;

    /** Test-seam constructor. */
    public RegistryApiClient(HttpGetter getter) {
        this.getter = getter;
    }

    /** Spring-managed constructor. */
    @org.springframework.beans.factory.annotation.Autowired
    public RegistryApiClient(
            @Value("${castellum.docker.probe.connect-timeout-ms:2000}") int connectTimeoutMs,
            @Value("${castellum.docker.probe.read-timeout-ms:5000}") int readTimeoutMs) {
        this(buildDefaultGetter(Duration.ofMillis(connectTimeoutMs), Duration.ofMillis(readTimeoutMs)));
    }

    // ---- Public GET-only methods (hardcoded paths, READ-ONLY invariant) ----

    /**
     * GET /v2/_catalog — list repository names.
     *
     * <p>A 401 → {@link Optional#empty()} — no extraction, no retry. (R3)
     *
     * @param host the registry host
     * @param port the registry port (typically 5000)
     * @return the catalog JSON body, or empty on failure / 401
     */
    public Optional<String> getCatalog(String host, int port) {
        return getter.get(buildUri(host, port, "/v2/_catalog"));
    }

    /**
     * GET /v2/{name}/tags/list — list tags for the given repository.
     *
     * <p><b>Security:</b> {@code name} is validated against the Docker repository-name grammar
     * BEFORE any network call is issued. Non-conforming names return {@link Optional#empty()}
     * without touching the getter (SSRF / URI-injection defence, R2).
     *
     * @param host the registry host
     * @param port the registry port
     * @param name the repository name (e.g. {@code "nginx"} or {@code "library/nginx"})
     * @return the tags JSON body, or empty on validation failure / network failure / 401
     */
    public Optional<String> getTags(String host, int port, String name) {
        if (name == null || name.length() > MAX_REPO_NAME_LENGTH
                || !REPO_NAME_PATTERN.matcher(name).matches()) {
            log.warn("RegistryApiClient: rejecting repository name that does not conform to Docker "
                    + "grammar (SSRF guard) — name={}", name);
            return Optional.empty();
        }
        return getter.get(buildUri(host, port, "/v2/" + name + "/tags/list"));
    }

    // ---- Private helpers ----

    private static URI buildUri(String host, int port, String path) {
        // Default Docker registry on :5000 uses HTTP
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
                    log.debug("RegistryApiClient {} returned HTTP {} — treating as empty (no retry)", uri, status);
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
                            log.warn("RegistryApiClient {} response exceeds {} bytes — rejecting", uri, MAX_BODY_BYTES);
                            return Optional.empty();
                        }
                        baos.write(buf, 0, read);
                    }
                    return Optional.of(baos.toString(java.nio.charset.StandardCharsets.UTF_8));
                }
            } catch (ConnectException | HttpTimeoutException e) {
                log.debug("RegistryApiClient {} unreachable: {}", uri, e.getMessage());
                return Optional.empty();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Optional.empty();
            } catch (IOException e) {
                String msg = e.getMessage();
                if (msg != null && (msg.contains("Connection refused") || msg.contains("refused"))) {
                    log.debug("RegistryApiClient {} connection refused", uri);
                } else {
                    log.debug("RegistryApiClient {} IO error: {}", uri, msg);
                }
                return Optional.empty();
            }
        };
    }
}
