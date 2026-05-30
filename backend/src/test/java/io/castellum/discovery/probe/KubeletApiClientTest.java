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
 * Unit tests for {@link KubeletApiClient}.
 * All tests use the {@link KubeletApiClient.HttpGetter} seam — no real sockets.
 */
class KubeletApiClientTest {

    private static String fixture(String name) throws IOException {
        try (InputStream in = KubeletApiClientTest.class.getResourceAsStream("/k8s/" + name)) {
            if (in == null) throw new IOException("fixture /k8s/" + name + " not found");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // (1) getPods returns fixture body
    @Test
    void getPods_returnsFixtureBody() throws Exception {
        String body = fixture("kubelet-pods.json");
        KubeletApiClient client = new KubeletApiClient(uri -> Optional.of(body));

        Optional<String> result = client.getPods("kubelet-host", 10255);

        assertThat(result).isPresent();
        assertThat(result.get()).contains("coredns-abc");
    }

    // (2) getPods captures the hardcoded path /pods over http
    @Test
    void getPods_buildsHardcodedPath() {
        List<URI> captured = new ArrayList<>();
        KubeletApiClient client = new KubeletApiClient(uri -> {
            captured.add(uri);
            return Optional.of("{\"items\":[]}");
        });

        client.getPods("192.168.1.50", 10255);

        assertThat(captured).hasSize(1);
        URI uri = captured.get(0);
        assertThat(uri.getScheme()).isEqualTo("http");
        assertThat(uri.getPath()).isEqualTo("/pods");
        assertThat(uri.getPort()).isEqualTo(10255);
    }

    // (3) Transport-empty → Optional.empty()
    @Test
    void getPods_transportEmpty_returnsEmpty() {
        KubeletApiClient client = new KubeletApiClient(uri -> Optional.empty());
        assertThat(client.getPods("10.0.0.50", 10255)).isEmpty();
    }

    // (4) REQUIRED single-shot no-retry test (R3)
    @Test
    void getPods_401simulation_singleShotNoRetry() {
        AtomicInteger callCount = new AtomicInteger(0);
        KubeletApiClient client = new KubeletApiClient(uri -> {
            callCount.incrementAndGet();
            return Optional.empty();
        });

        client.getPods("10.0.0.50", 10255);

        assertThat(callCount.get())
            .as("getter must be invoked EXACTLY ONCE — no retry (R3)")
            .isEqualTo(1);
    }

    // (5) R4 reflection surface — every public method starts with 'get'
    @Test
    void r4_reflectionSurface_allPublicMethodsStartWithGet() {
        for (Method m : KubeletApiClient.class.getMethods()) {
            if (m.getDeclaringClass().equals(Object.class)) continue;
            if (!Modifier.isPublic(m.getModifiers())) continue;
            String name = m.getName();
            assertThat(name)
                .as("public method '%s' must start with 'get' (READ-ONLY R4 invariant)", name)
                .matches("get.*|equals|hashCode|toString|getClass|wait|notify|notifyAll");
        }
    }
}
