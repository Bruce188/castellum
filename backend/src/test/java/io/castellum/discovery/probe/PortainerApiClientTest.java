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
 * Unit tests for {@link PortainerApiClient} using the HttpGetter seam.
 */
class PortainerApiClientTest {

    private static String fixture(String name) throws Exception {
        try (var in = PortainerApiClientTest.class.getResourceAsStream("/docker/" + name)) {
            if (in == null) throw new IllegalArgumentException("fixture " + name + " not found");
            return new String(in.readAllBytes());
        }
    }

    @Test
    void getStatus_detect_returnsStatusJson() throws Exception {
        String statusJson = fixture("portainer-status.json");
        List<URI> capturedUris = new ArrayList<>();

        PortainerApiClient client = new PortainerApiClient(uri -> {
            capturedUris.add(uri);
            return Optional.of(statusJson);
        });

        Optional<String> result = client.getStatus("10.0.0.1", 9000);
        assertThat(result).isPresent();
        assertThat(result.get()).contains("Version");
        assertThat(capturedUris.get(0).getPath()).isEqualTo("/api/status");
    }

    @Test
    void getEndpoints_noAuth_returnsData() throws Exception {
        String endpointsJson = fixture("portainer-endpoints.json");
        List<URI> capturedUris = new ArrayList<>();

        PortainerApiClient client = new PortainerApiClient(uri -> {
            capturedUris.add(uri);
            return Optional.of(endpointsJson);
        });

        Optional<String> result = client.getEndpoints("10.0.0.1", 9000);
        assertThat(result).isPresent();
        assertThat(result.get()).contains("remote-host");
        assertThat(capturedUris.get(0).getPath()).isEqualTo("/api/endpoints");
    }

    @Test
    void getEndpoints_authRequired_returnsEmpty() {
        // Simulate 401 response by returning empty (buildDefaultGetter returns empty on 401)
        // For the seam test we simulate the getter returning empty directly (same effect)
        PortainerApiClient client = new PortainerApiClient(uri -> Optional.empty());
        Optional<String> result = client.getEndpoints("10.0.0.1", 9000);
        assertThat(result).isEmpty();
    }

    @Test
    void getStatus_connectionFailed_returnsEmpty() {
        PortainerApiClient client = new PortainerApiClient(uri -> Optional.empty());
        assertThat(client.getStatus("10.0.0.1", 9000)).isEmpty();
    }

    // ---- R4: reflection — no auth/verb/body methods ----

    @Test
    void reflectionSurface_noAuthVerbBodyMethods() {
        Method[] methods = PortainerApiClient.class.getMethods();
        for (Method m : methods) {
            if (m.getDeclaringClass() == Object.class) continue;
            String name = m.getName();
            assertThat(name)
                .as("No auth/verb/body method allowed (R10)")
                .doesNotStartWith("login")
                .doesNotStartWith("auth")
                .doesNotStartWith("post")
                .doesNotStartWith("put")
                .doesNotStartWith("delete")
                .doesNotStartWith("set");
        }
        // Positive: getStatus and getEndpoints exist
        assertThat(Arrays.stream(methods).map(Method::getName))
            .contains("getStatus", "getEndpoints");
    }
}
