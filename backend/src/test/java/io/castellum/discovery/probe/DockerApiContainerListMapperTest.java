package io.castellum.discovery.probe;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DockerApiContainerListMapper}.
 */
class DockerApiContainerListMapperTest {

    private static final DockerApiContainerListMapper mapper = new DockerApiContainerListMapper();

    private static String fixture(String name) throws IOException {
        try (InputStream in = DockerApiContainerListMapperTest.class.getResourceAsStream("/docker/" + name)) {
            if (in == null) throw new IOException("fixture /docker/" + name + " not found");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // (1) api-containers-list.json → expected IDs
    @Test
    void containerIds_fixtureJson_extractsIds() throws Exception {
        String json = fixture("api-containers-list.json");
        List<String> ids = mapper.containerIds(json);

        assertThat(ids).hasSize(2);
        assertThat(ids).contains(
            "a1b2c3d4e5f600000000000000000000000000000000000000000000000000pf",
            "a1b2c3d4e5f600000000000000000000000000000000000000000000000000db"
        );
    }

    // (2) blank → empty
    @Test
    void containerIds_blank_returnsEmpty() {
        assertThat(mapper.containerIds("")).isEmpty();
        assertThat(mapper.containerIds("   ")).isEmpty();
        assertThat(mapper.containerIds(null)).isEmpty();
    }

    // (3) malformed JSON → IllegalArgumentException
    @Test
    void containerIds_malformedJson_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> mapper.containerIds("{bad"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    // (4) empty array → empty list
    @Test
    void containerIds_emptyArray_returnsEmpty() {
        assertThat(mapper.containerIds("[]")).isEmpty();
    }

    // (5) non-array JSON → empty list
    @Test
    void containerIds_nonArray_returnsEmpty() {
        assertThat(mapper.containerIds("{}")).isEmpty();
    }
}
