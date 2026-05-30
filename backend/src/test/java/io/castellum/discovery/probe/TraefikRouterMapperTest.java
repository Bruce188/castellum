package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link TraefikRouterMapper}.
 */
class TraefikRouterMapperTest {

    private static final ObjectMapper OM = new ObjectMapper();
    private final TraefikRouterMapper mapper = new TraefikRouterMapper(OM);

    private static String fixture(String name) throws Exception {
        try (var in = TraefikRouterMapperTest.class.getResourceAsStream("/docker/" + name)) {
            if (in == null) throw new IllegalArgumentException("fixture " + name + " not found");
            return new String(in.readAllBytes());
        }
    }

    @Test
    void backendContainerNames_fixtureRouters_extractsServiceNames() throws Exception {
        String routersJson = fixture("traefik-routers.json");
        String servicesJson = fixture("traefik-services.json");

        List<String> names = mapper.backendContainerNames(routersJson, servicesJson);

        assertThat(names).containsExactlyInAnyOrder("frontend-svc", "api-svc");
    }

    @Test
    void backendContainerNames_malformedRouterEntry_skipped() {
        String routersJson = """
            [{"service":"good-svc","rule":"Host(`example.com`)"},{"notAService":true}]
            """;
        List<String> names = mapper.backendContainerNames(routersJson, null);
        // Malformed entry (no "service" key) skipped; "good-svc" still extracted
        assertThat(names).containsExactly("good-svc");
    }

    @Test
    void backendContainerNames_emptyInput_returnsEmpty() {
        assertThat(mapper.backendContainerNames(null, null)).isEmpty();
        assertThat(mapper.backendContainerNames("", null)).isEmpty();
        assertThat(mapper.backendContainerNames("   ", null)).isEmpty();
    }

    @Test
    void backendContainerNames_invalidJson_returnsEmpty() {
        assertThat(mapper.backendContainerNames("{not valid}", null)).isEmpty();
    }
}
