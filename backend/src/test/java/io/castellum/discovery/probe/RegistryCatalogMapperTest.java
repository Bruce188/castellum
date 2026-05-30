package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RegistryCatalogMapper}.
 */
class RegistryCatalogMapperTest {

    private static final ObjectMapper OM = new ObjectMapper();
    private static final RegistryCatalogMapper MAPPER = new RegistryCatalogMapper(OM);

    private static String fixture(String name) throws IOException {
        try (InputStream in = RegistryCatalogMapperTest.class.getResourceAsStream("/k8s/" + name)) {
            if (in == null) throw new IOException("fixture /k8s/" + name + " not found");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void repositories_catalogFixture_returnsRepoList() throws Exception {
        String json = fixture("registry-catalog.json");
        List<String> repos = MAPPER.repositories(json);

        assertThat(repos).containsExactly("nginx", "redis", "myapp");
    }

    @Test
    void tags_tagsFixture_returnsTagList() throws Exception {
        String json = fixture("registry-tags.json");
        List<String> tags = MAPPER.tags(json);

        assertThat(tags).containsExactly("latest", "1.25");
    }

    @Test
    void toInventoryBlob_repoList_returnsCommaSeparated() {
        String blob = MAPPER.toInventoryBlob(List.of("nginx", "redis", "myapp"));
        assertThat(blob).isEqualTo("nginx,redis,myapp");
    }

    @Test
    void toInventoryBlob_emptyList_returnsEmptyString() {
        assertThat(MAPPER.toInventoryBlob(List.of())).isEqualTo("");
        assertThat(MAPPER.toInventoryBlob(null)).isEqualTo("");
    }

    @Test
    void repositories_malformedJson_returnsEmptyList() {
        assertThat(MAPPER.repositories("{not valid{")).isEmpty();
    }

    @Test
    void repositories_blankInput_returnsEmptyList() {
        assertThat(MAPPER.repositories("")).isEmpty();
        assertThat(MAPPER.repositories(null)).isEmpty();
        assertThat(MAPPER.repositories("   ")).isEmpty();
    }

    @Test
    void tags_malformedJson_returnsEmptyList() {
        assertThat(MAPPER.tags("{bad")).isEmpty();
    }

    @Test
    void repositories_overCapCount_truncated() {
        int cap = DockerHostProbeService.MAX_CONTAINERS_PER_HOST;
        StringBuilder sb = new StringBuilder("{\"repositories\":[");
        for (int i = 0; i <= cap; i++) {
            if (i > 0) sb.append(",");
            sb.append("\"repo").append(i).append("\"");
        }
        sb.append("]}");
        List<String> result = MAPPER.repositories(sb.toString());
        assertThat(result).hasSize(cap);
    }
}
