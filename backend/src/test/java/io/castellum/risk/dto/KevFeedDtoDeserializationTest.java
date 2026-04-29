package io.castellum.risk.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class KevFeedDtoDeserializationTest {

    @Test
    void deserializes_kevSampleFixture() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        try (var stream = getClass().getResourceAsStream("/kev/kev-sample.json")) {
            KevFeedDto feed = mapper.readValue(stream, KevFeedDto.class);
            assertThat(feed.count()).isEqualTo(feed.vulnerabilities().size());
            assertThat(feed.count()).isEqualTo(3);
            var openssh = feed.vulnerabilities().stream()
                .filter(v -> "CVE-2020-15778".equals(v.cveId())).findFirst().orElseThrow();
            assertThat(openssh.dateAdded()).isEqualTo("2022-02-15");
            assertThat(openssh.vendorProject()).isEqualTo("OpenBSD");
            assertThat(openssh.cwes()).containsExactly("CWE-78");
        }
    }
}
