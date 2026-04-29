package io.castellum.cve.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class NvdResponseDeserializationTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void deserialize_fixture_succeeds() throws Exception {
        InputStream is = getClass().getResourceAsStream("/cve/nvd-page-sample.json");
        assertNotNull(is, "Fixture file must be on the classpath at /cve/nvd-page-sample.json");

        NvdCveResponse response = mapper.readValue(is, NvdCveResponse.class);

        assertNotNull(response);
        assertTrue(response.totalResults() > 0, "totalResults must be positive");
        assertFalse(response.vulnerabilities().isEmpty(), "vulnerabilities must be non-empty");
        assertEquals(response.vulnerabilities().size(), response.resultsPerPage(),
            "vulnerabilities size should match resultsPerPage in this fixture");
    }

    @Test
    void deserialize_cve2020_15778_hasExpectedCpeMatchWithVersionEndExcluding() throws Exception {
        InputStream is = getClass().getResourceAsStream("/cve/nvd-page-sample.json");
        NvdCveResponse response = mapper.readValue(is, NvdCveResponse.class);

        Optional<NvdVulnerability> cve15778 = response.vulnerabilities().stream()
            .filter(v -> "CVE-2020-15778".equals(v.cve().id()))
            .findFirst();

        assertTrue(cve15778.isPresent(), "CVE-2020-15778 must be present in the fixture");

        NvdCveItem item = cve15778.get().cve();
        assertNotNull(item.configurations(), "configurations must not be null");
        assertFalse(item.configurations().isEmpty(), "configurations must be non-empty");

        NvdNode firstNode = item.configurations().get(0).nodes().get(0);
        assertFalse(firstNode.cpeMatch().isEmpty(), "cpeMatch must be non-empty");

        NvdCpeMatch match = firstNode.cpeMatch().get(0);
        assertTrue(Boolean.TRUE.equals(match.vulnerable()), "match must be vulnerable");
        assertEquals("8.4", match.versionEndExcluding(),
            "CVE-2020-15778 must have versionEndExcluding=8.4");
        assertTrue(match.criteria().contains("openbsd:openssh"),
            "criteria must reference openbsd:openssh");
    }
}
