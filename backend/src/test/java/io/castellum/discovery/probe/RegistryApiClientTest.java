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
}
