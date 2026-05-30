package io.castellum.discovery.probe;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RegistryApiClient}.
 * All tests use the {@link RegistryApiClient.HttpGetter} seam — no real sockets.
 */
class RegistryApiClientTest {

    private static String fixture(String name) throws IOException {
        try (InputStream in = RegistryApiClientTest.class.getResourceAsStream("/k8s/" + name)) {
            if (in == null) throw new IOException("fixture /k8s/" + name + " not found");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void getCatalog_returnsFixtureBody() throws Exception {
        String body = fixture("registry-catalog.json");
        RegistryApiClient client = new RegistryApiClient(uri -> Optional.of(body));

        Optional<String> result = client.getCatalog("registry-host", 5000);

        assertThat(result).isPresent();
        assertThat(result.get()).contains("nginx", "redis", "myapp");
    }

    @Test
    void getCatalog_buildsHardcodedPath() {
        List<URI> captured = new ArrayList<>();
        RegistryApiClient client = new RegistryApiClient(uri -> {
            captured.add(uri);
            return Optional.of("{\"repositories\":[]}");
        });

        client.getCatalog("192.168.1.50", 5000);

        assertThat(captured).hasSize(1);
        URI uri = captured.get(0);
        assertThat(uri.getScheme()).isEqualTo("http");
        assertThat(uri.getPath()).isEqualTo("/v2/_catalog");
        assertThat(uri.getPort()).isEqualTo(5000);
    }

    @Test
    void getTags_buildsHardcodedPath() {
        List<URI> captured = new ArrayList<>();
        RegistryApiClient client = new RegistryApiClient(uri -> {
            captured.add(uri);
            return Optional.of("{\"name\":\"nginx\",\"tags\":[]}");
        });

        client.getTags("192.168.1.50", 5000, "nginx");

        assertThat(captured).hasSize(1);
        assertThat(captured.get(0).getPath()).isEqualTo("/v2/nginx/tags/list");
    }

    @Test
    void getCatalog_transportEmpty_returnsEmpty() {
        RegistryApiClient client = new RegistryApiClient(uri -> Optional.empty());
        assertThat(client.getCatalog("10.0.0.50", 5000)).isEmpty();
    }

    @Test
    void getCatalog_401simulation_singleShotNoRetry() {
        AtomicInteger callCount = new AtomicInteger(0);
        RegistryApiClient client = new RegistryApiClient(uri -> {
            callCount.incrementAndGet();
            return Optional.empty(); // simulates 401
        });

        client.getCatalog("10.0.0.50", 5000);

        assertThat(callCount.get())
            .as("getter must be invoked EXACTLY ONCE — no retry on 401 (R3)")
            .isEqualTo(1);
    }

    @Test
    void r4_reflectionSurface_allPublicMethodsStartWithGet() {
        for (Method m : RegistryApiClient.class.getMethods()) {
            if (m.getDeclaringClass().equals(Object.class)) continue;
            if (!Modifier.isPublic(m.getModifiers())) continue;
            String name = m.getName();
            assertThat(name)
                .as("public method '%s' must start with 'get' (READ-ONLY R4 invariant)", name)
                .matches("get.*|equals|hashCode|toString|getClass|wait|notify|notifyAll");
        }
    }

    // -----------------------------------------------------------------------
    // R2 BLOCKING #1 — SSRF / URI-injection via untrusted registry repo names
    //
    // RegistryApiClient.getTags(host, port, name) must validate `name` against the
    // Docker repository-name grammar and REJECT non-conforming names WITHOUT issuing
    // any HTTP request. A capturing getter records every URI the client was asked to
    // fetch; for malicious names the capture list must stay empty (no off-host GET).
    // -----------------------------------------------------------------------

    /**
     * Malicious repository names returned by a crafted registry _catalog must be
     * rejected BEFORE any network call is made.
     *
     * <p>Each of the names below violates Docker's repository-name grammar in a way
     * that would redirect or otherwise mutate the constructed URI:
     * <ul>
     *   <li>{@code "nginx@attacker.com/pwn"} — {@code @} is not a legal repo-name char;
     *       URI.create would include the authority fragment, redirecting the request.</li>
     *   <li>{@code "../../etc/passwd"} — path traversal via dots.</li>
     *   <li>{@code "evil?x"} — {@code ?} injects a query string into the URI.</li>
     *   <li>{@code "evil#x"} — {@code #} injects a fragment into the URI.</li>
     *   <li>{@code "a%0d%0aX"} — CRLF injection via percent-encoded bytes.</li>
     * </ul>
     *
     * <p>RED until {@link RegistryApiClient#getTags} validates {@code name} and
     * short-circuits before calling the getter.
     */
    @Test
    void getTags_maliciousName_rejectedNoRequest() {
        List<String> maliciousNames = List.of(
            "nginx@attacker.com/pwn",
            "../../etc/passwd",
            "evil?x",
            "evil#x",
            "a%0d%0aX"
        );

        for (String maliciousName : maliciousNames) {
            List<URI> capturedUris = new ArrayList<>();
            RegistryApiClient client = new RegistryApiClient(uri -> {
                capturedUris.add(uri);
                return Optional.of("{\"name\":\"evil\",\"tags\":[]}");
            });

            Optional<String> result = client.getTags("trusted-registry.internal", 5000, maliciousName);

            assertThat(result)
                .as("getTags must return empty for malicious name '%s' (SSRF rejection)", maliciousName)
                .isEmpty();
            assertThat(capturedUris)
                .as("getter must NOT be called for malicious name '%s' — validation must reject before any network call",
                    maliciousName)
                .isEmpty();
        }
    }

    /**
     * Legitimate Docker repository names must still reach the getter with the
     * correct URI — host/authority must equal the ORIGINAL host:port, and the path
     * must be exactly {@code /v2/<name>/tags/list}.
     *
     * <p>Docker repository names allow lowercase letters, digits, hyphens, dots,
     * and a single {@code /} as a namespace separator (e.g. {@code "library/nginx"}).
     *
     * <p>RED until validation accepts these names and delegates the request.
     */
    @Test
    void getTags_validName_issuesOnHostRequest() {
        List<String> validNames = List.of("nginx", "library/nginx");

        for (String validName : validNames) {
            List<URI> capturedUris = new ArrayList<>();
            RegistryApiClient client = new RegistryApiClient(uri -> {
                capturedUris.add(uri);
                return Optional.of("{\"name\":\"" + validName + "\",\"tags\":[\"latest\"]}");
            });

            Optional<String> result = client.getTags("trusted-registry.internal", 5000, validName);

            assertThat(capturedUris)
                .as("getter must be called exactly once for valid name '%s'", validName)
                .hasSize(1);

            URI issued = capturedUris.get(0);
            assertThat(issued.getScheme())
                .as("URI scheme must be 'http' for valid name '%s'", validName)
                .isEqualTo("http");
            assertThat(issued.getHost())
                .as("URI host must equal the original host for valid name '%s'", validName)
                .isEqualTo("trusted-registry.internal");
            assertThat(issued.getPort())
                .as("URI port must equal the original port for valid name '%s'", validName)
                .isEqualTo(5000);
            assertThat(issued.getPath())
                .as("URI path must be /v2/<name>/tags/list for valid name '%s'", validName)
                .isEqualTo("/v2/" + validName + "/tags/list");
            // No unexpected query or fragment must have been injected
            assertThat(issued.getQuery())
                .as("URI must not have a query component for valid name '%s'", validName)
                .isNull();
            assertThat(issued.getFragment())
                .as("URI must not have a fragment component for valid name '%s'", validName)
                .isNull();
            // Authority must stay on the ORIGINAL host:port — not redirected off-host
            assertThat(issued.getAuthority())
                .as("URI authority must equal 'trusted-registry.internal:5000' for valid name '%s'", validName)
                .isEqualTo("trusted-registry.internal:5000");

            assertThat(result)
                .as("getTags must return a non-empty result for valid name '%s'", validName)
                .isPresent();
        }
    }
}
