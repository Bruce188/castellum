package io.castellum.discovery.probe;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link TraefikApiClient} using the HttpGetter seam.
 */
class TraefikApiClientTest {

    // ---- Fixture helper ----

    private static String fixture(String name) throws Exception {
        try (var in = TraefikApiClientTest.class.getResourceAsStream("/docker/" + name)) {
            if (in == null) throw new IllegalArgumentException("fixture " + name + " not found");
            return new String(in.readAllBytes());
        }
    }

    @Test
    void getRouters_fixtureGetter_returnsBody() throws Exception {
        String routersJson = fixture("traefik-routers.json");
        List<URI> capturedUris = new ArrayList<>();

        DockerEngineApiClient.HttpGetter getter = uri -> {
            capturedUris.add(uri);
            return Optional.of(routersJson);
        };

        TraefikApiClient client = new TraefikApiClient(getter);
        Optional<String> result = client.getRouters("10.0.0.1", 8080);

        assertThat(result).isPresent();
        assertThat(result.get()).contains("frontend-router");
        // Verify URI path
        assertThat(capturedUris).hasSize(1);
        assertThat(capturedUris.get(0).getPath()).isEqualTo("/api/http/routers");
    }

    @Test
    void getServices_capturesCorrectUri() {
        List<URI> capturedUris = new ArrayList<>();
        TraefikApiClient client = new TraefikApiClient(uri -> {
            capturedUris.add(uri);
            return Optional.of("[]");
        });

        client.getServices("10.0.0.2", 8080);

        assertThat(capturedUris).hasSize(1);
        assertThat(capturedUris.get(0).getPath()).isEqualTo("/api/http/services");
    }

    @Test
    void getOverview_capturesCorrectUri() throws Exception {
        String overviewJson = fixture("traefik-overview.json");
        List<URI> capturedUris = new ArrayList<>();
        TraefikApiClient client = new TraefikApiClient(uri -> {
            capturedUris.add(uri);
            return Optional.of(overviewJson);
        });

        Optional<String> result = client.getOverview("10.0.0.3", 8080);

        assertThat(result).isPresent();
        assertThat(result.get()).contains("traefikVersion");
        assertThat(capturedUris.get(0).getPath()).isEqualTo("/api/overview");
    }

    @Test
    void transportEmpty_returnsEmpty() {
        TraefikApiClient client = new TraefikApiClient(uri -> Optional.empty());
        assertThat(client.getRouters("10.0.0.1", 8080)).isEmpty();
        assertThat(client.getServices("10.0.0.1", 8080)).isEmpty();
        assertThat(client.getOverview("10.0.0.1", 8080)).isEmpty();
    }

    // ---- R4: reflection surface test ----

    @Test
    void reflectionSurface_allPublicMethodsStartWithGet_noVerbBody() {
        Method[] methods = TraefikApiClient.class.getMethods();
        for (Method m : methods) {
            if (m.getDeclaringClass() == Object.class) continue;
            String name = m.getName();
            // No method should expose a verb or body param setter
            assertThat(name).as("No public method should be named 'set*' or 'post*' or 'put*'")
                .doesNotStartWith("set")
                .doesNotStartWith("post")
                .doesNotStartWith("put")
                .doesNotStartWith("delete")
                .doesNotStartWith("patch");
        }
        // Positive assertion: get* methods exist
        assertThat(Arrays.stream(methods).map(Method::getName))
            .contains("getRouters", "getServices", "getOverview");
    }
}
