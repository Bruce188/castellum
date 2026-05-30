package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link CAdvisorContainerMapper}.
 */
class CAdvisorContainerMapperTest {

    private static final ObjectMapper OM = new ObjectMapper();
    private final CAdvisorContainerMapper mapper = new CAdvisorContainerMapper(OM);

    private static String fixture(String name) throws Exception {
        try (var in = CAdvisorContainerMapperTest.class.getResourceAsStream("/docker/" + name)) {
            if (in == null) throw new IllegalArgumentException("fixture " + name + " not found");
            return new String(in.readAllBytes());
        }
    }

    @Test
    void containerNames_fixtureSubcontainers_extractsNames() throws Exception {
        String json = fixture("cadvisor-subcontainers.json");
        List<String> names = mapper.containerNames(json);
        // Fixture has labels for "webapp" and "database"
        assertThat(names).containsExactlyInAnyOrder("webapp", "database");
    }

    @Test
    void containerNames_noLabelFallsBackToAlias() {
        String json = """
            [{"id":"x","aliases":["my-alias","x"],"labels":{},"spec":{}}]
            """;
        List<String> names = mapper.containerNames(json);
        assertThat(names).containsExactly("my-alias");
    }

    @Test
    void containerNames_malformedEntry_skipped() {
        String json = """
            [{"id":"good","aliases":["good-one"],"labels":{},"spec":{}},
             {"broken":true}]
            """;
        List<String> names = mapper.containerNames(json);
        assertThat(names).containsExactly("good-one");
    }

    @Test
    void containerNames_emptyInput_returnsEmpty() {
        assertThat(mapper.containerNames(null)).isEmpty();
        assertThat(mapper.containerNames("")).isEmpty();
        assertThat(mapper.containerNames("   ")).isEmpty();
    }

    @Test
    void containerNames_invalidJson_returnsEmpty() {
        assertThat(mapper.containerNames("{not-array}")).isEmpty();
    }
}
