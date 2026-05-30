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
 * Unit tests for {@link K8sApiClient}.
 * All tests use the {@link K8sApiClient.HttpGetter} seam — no real sockets.
 */
class K8sApiClientTest {

    private static String fixture(String name) throws IOException {
        try (InputStream in = K8sApiClientTest.class.getResourceAsStream("/k8s/" + name)) {
            if (in == null) throw new IOException("fixture /k8s/" + name + " not found");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // (1) getPods returns fixture body and captures the correct path
    @Test
    void getPods_returnsFixtureBody() throws Exception {
        String body = fixture("k8s-pods.json");
        K8sApiClient client = new K8sApiClient(uri -> Optional.of(body));

        Optional<String> result = client.getPods("k8s-host", 6443);

        assertThat(result).isPresent();
        assertThat(result.get()).contains("nginx-deployment-abc12");
    }

    // (2) getSecrets captures the hardcoded path /api/v1/namespaces/{ns}/secrets
    @Test
    void getSecrets_buildsHardcodedPath() throws Exception {
        List<URI> captured = new ArrayList<>();
        K8sApiClient client = new K8sApiClient(uri -> {
            captured.add(uri);
            return Optional.of("{\"items\":[]}");
        });

        client.getSecrets("10.0.0.50", 6443, "default");

        assertThat(captured).hasSize(1);
        URI uri = captured.get(0);
        assertThat(uri.getScheme()).isEqualTo("https");
        assertThat(uri.getPath()).isEqualTo("/api/v1/namespaces/default/secrets");
        assertThat(uri.getPort()).isEqualTo(6443);
    }

    // (3) getPods captures the hardcoded path /api/v1/pods
    @Test
    void getPods_buildsHardcodedPath() {
        List<URI> captured = new ArrayList<>();
        K8sApiClient client = new K8sApiClient(uri -> {
            captured.add(uri);
            return Optional.of("{\"items\":[]}");
        });

        client.getPods("192.168.1.50", 6443);

        assertThat(captured).hasSize(1);
        assertThat(captured.get(0).getPath()).isEqualTo("/api/v1/pods");
        assertThat(captured.get(0).getScheme()).isEqualTo("https");
    }

    // (4) getNamespaces captures the hardcoded path /api/v1/namespaces
    @Test
    void getNamespaces_buildsHardcodedPath() {
        List<URI> captured = new ArrayList<>();
        K8sApiClient client = new K8sApiClient(uri -> {
            captured.add(uri);
            return Optional.of("{\"items\":[]}");
        });

        client.getNamespaces("192.168.1.50", 6443);

        assertThat(captured).hasSize(1);
        assertThat(captured.get(0).getPath()).isEqualTo("/api/v1/namespaces");
    }

    // (5) Transport-empty (simulating 401) → Optional.empty()
    @Test
    void getPods_transportEmpty_returnsEmpty() {
        K8sApiClient client = new K8sApiClient(uri -> Optional.empty());
        assertThat(client.getPods("10.0.0.50", 6443)).isEmpty();
    }

    // (6) REQUIRED 401-single-shot no-retry test (R3)
    // Simulates a getter that returns empty (as a 401 would) — must be invoked EXACTLY ONCE.
    @Test
    void getPods_401simulation_singleShotNoRetry() {
        AtomicInteger callCount = new AtomicInteger(0);
        K8sApiClient client = new K8sApiClient(uri -> {
            callCount.incrementAndGet();
            return Optional.empty(); // simulates 401 back-off
        });

        client.getPods("10.0.0.50", 6443);

        assertThat(callCount.get())
            .as("getter must be invoked EXACTLY ONCE — no retry on 401/403 (R3)")
            .isEqualTo(1);
    }

    // (7) R4 reflection surface — every public method starts with 'get'; none admits verb/body
    @Test
    void r4_reflectionSurface_allPublicMethodsStartWithGet() {
        for (Method m : K8sApiClient.class.getMethods()) {
            if (m.getDeclaringClass().equals(Object.class)) continue;
            if (!Modifier.isPublic(m.getModifiers())) continue;
            // Skip constructors (not methods)
            String name = m.getName();
            assertThat(name)
                .as("public method '%s' must start with 'get' (READ-ONLY R4 invariant)", name)
                .matches("get.*|equals|hashCode|toString|getClass|wait|notify|notifyAll");
        }
    }

    // (8) fixture round-trip: getSecrets returns fixture body
    @Test
    void getSecrets_returnsFixtureBody() throws Exception {
        String body = fixture("k8s-secrets.json");
        K8sApiClient client = new K8sApiClient(uri -> Optional.of(body));

        Optional<String> result = client.getSecrets("k8s-host", 6443, "default");

        assertThat(result).isPresent();
        assertThat(result.get()).contains("default-token-abcde");
    }
}
