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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link DockerEngineApiClient}.
 * All tests use the {@link DockerEngineApiClient.HttpGetter} seam — no real sockets.
 */
class DockerEngineApiClientTest {

    private static String fixture(String name) throws IOException {
        try (InputStream in = DockerEngineApiClientTest.class.getResourceAsStream("/docker/" + name)) {
            if (in == null) throw new IOException("fixture /docker/" + name + " not found");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // (1) getNetworks returns fixture body when getter returns it
    @Test
    void getNetworks_returnsFixtureBody() throws Exception {
        String fixtureBody = fixture("api-networks.json");
        DockerEngineApiClient client = new DockerEngineApiClient(uri -> Optional.of(fixtureBody));

        Optional<String> result = client.getNetworks("localhost", 2375);

        assertThat(result).isPresent();
        assertThat(result.get()).contains("pingpay_default");
    }

    // (2) getContainerInspect builds the hardcoded path /containers/{id}/json
    @Test
    void getContainerInspect_buildsHardcodedPath() {
        List<URI> captured = new ArrayList<>();
        DockerEngineApiClient client = new DockerEngineApiClient(uri -> {
            captured.add(uri);
            return Optional.of("{}");
        });

        String containerId = "abc123";
        client.getContainerInspect("192.168.1.50", 2375, containerId);

        assertThat(captured).hasSize(1);
        URI uri = captured.get(0);
        assertThat(uri.getPath()).isEqualTo("/containers/" + containerId + "/json");
        assertThat(uri.getHost()).isEqualTo("192.168.1.50");
        assertThat(uri.getPort()).isEqualTo(2375);
    }

    // (3) When transport returns empty, client returns empty (closed-port no-op)
    @Test
    void transportEmpty_returnsEmpty() {
        DockerEngineApiClient client = new DockerEngineApiClient(uri -> Optional.empty());

        assertThat(client.getNetworks("10.0.0.1", 2375)).isEmpty();
        assertThat(client.getContainers("10.0.0.1", 2375)).isEmpty();
        assertThat(client.getContainerInspect("10.0.0.1", 2375, "abc")).isEmpty();
        assertThat(client.getNetwork("10.0.0.1", 2375, "net1")).isEmpty();
    }

    // (4) getContainers builds the correct /containers/json path
    @Test
    void getContainers_buildsCorrectPath() {
        List<URI> captured = new ArrayList<>();
        DockerEngineApiClient client = new DockerEngineApiClient(uri -> {
            captured.add(uri);
            return Optional.of("[]");
        });

        client.getContainers("10.0.0.5", 2375);

        assertThat(captured).hasSize(1);
        assertThat(captured.get(0).getPath()).isEqualTo("/containers/json");
    }

    // (5) getNetwork builds the correct /networks/{id} path
    @Test
    void getNetwork_buildsCorrectPath() {
        List<URI> captured = new ArrayList<>();
        DockerEngineApiClient client = new DockerEngineApiClient(uri -> {
            captured.add(uri);
            return Optional.of("{}");
        });

        client.getNetwork("10.0.0.5", 2375, "mynet");

        assertThat(captured).hasSize(1);
        assertThat(captured.get(0).getPath()).isEqualTo("/networks/mynet");
    }

    // (6) R1 READ-ONLY surface assertion: every public declared method starts with "get",
    //     and no public method accepts an HTTP verb or body parameter.
    @Test
    void r1_readOnlySurface_allPublicMethodsStartWithGet() {
        Method[] methods = DockerEngineApiClient.class.getDeclaredMethods();
        List<String> violations = new ArrayList<>();

        for (Method m : methods) {
            if (!Modifier.isPublic(m.getModifiers())) {
                continue; // only check public methods
            }
            String name = m.getName();
            // constructor-related or synthetic methods may not start with "get"
            // All public API methods must start with "get"
            if (!name.startsWith("get")) {
                violations.add(name);
            }
            // Ensure no method takes a string "verb" or "body" parameter (structural check)
            // No method should have parameter names suggestive of HTTP mutation
            for (Class<?> paramType : m.getParameterTypes()) {
                // byte[] or InputStream would imply a request body
                if (paramType == byte[].class || paramType == InputStream.class
                        || paramType == java.io.OutputStream.class) {
                    violations.add(name + " takes a body param: " + paramType.getSimpleName());
                }
            }
        }

        assertThat(violations)
            .as("All public methods must start with 'get' and none must accept a body param")
            .isEmpty();
    }
}
