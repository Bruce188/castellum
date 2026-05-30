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
 * Unit tests for {@link CAdvisorApiClient} using the HttpGetter seam.
 */
class CAdvisorApiClientTest {

    private static String fixture(String name) throws Exception {
        try (var in = CAdvisorApiClientTest.class.getResourceAsStream("/docker/" + name)) {
            if (in == null) throw new IllegalArgumentException("fixture " + name + " not found");
            return new String(in.readAllBytes());
        }
    }

    @Test
    void getSubcontainers_capturesUri() throws Exception {
        String body = fixture("cadvisor-subcontainers.json");
        List<URI> capturedUris = new ArrayList<>();

        CAdvisorApiClient client = new CAdvisorApiClient(uri -> {
            capturedUris.add(uri);
            return Optional.of(body);
        });

        Optional<String> result = client.getSubcontainers("10.0.0.1", 8080);
        assertThat(result).isPresent();
        assertThat(result.get()).contains("webapp");
        assertThat(capturedUris.get(0).getPath()).isEqualTo("/api/v1.3/subcontainers");
    }

    @Test
    void getMachine_capturesUri() throws Exception {
        String body = fixture("cadvisor-machine.json");
        List<URI> capturedUris = new ArrayList<>();

        CAdvisorApiClient client = new CAdvisorApiClient(uri -> {
            capturedUris.add(uri);
            return Optional.of(body);
        });

        Optional<String> result = client.getMachine("10.0.0.1", 8080);
        assertThat(result).isPresent();
        assertThat(result.get()).contains("num_cores");
        assertThat(capturedUris.get(0).getPath()).isEqualTo("/api/v1.3/machine");
    }

    @Test
    void transportEmpty_returnsEmpty() {
        CAdvisorApiClient client = new CAdvisorApiClient(uri -> Optional.empty());
        assertThat(client.getSubcontainers("10.0.0.1", 8080)).isEmpty();
        assertThat(client.getMachine("10.0.0.1", 8080)).isEmpty();
    }

    // ---- R4: reflection surface test ----

    @Test
    void reflectionSurface_allPublicMethodsStartWithGet_noVerbBody() {
        Method[] methods = CAdvisorApiClient.class.getMethods();
        for (Method m : methods) {
            if (m.getDeclaringClass() == Object.class) continue;
            String name = m.getName();
            assertThat(name)
                .doesNotStartWith("set")
                .doesNotStartWith("post")
                .doesNotStartWith("put")
                .doesNotStartWith("delete")
                .doesNotStartWith("patch");
        }
        assertThat(Arrays.stream(methods).map(Method::getName))
            .contains("getSubcontainers", "getMachine");
    }
}
