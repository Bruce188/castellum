package io.castellum.cve;

import io.castellum.cve.dto.NvdCveResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

@RestClientTest(NvdClient.class)
@TestPropertySource(properties = {
    "castellum.nvd.base-url=https://test.nvd.example/rest/json/cves/2.0",
    "castellum.nvd.api-key=test-key",
    "castellum.nvd.request-interval-millis=10"
})
class NvdClientApiKeyTest {

    @Autowired
    NvdClient client;

    @Autowired
    MockRestServiceServer server;

    @Value("classpath:cve/nvd-page-sample.json")
    Resource fixture;

    @Test
    void fetchPage_setsApiKeyHeaderWhenConfigured() throws Exception {
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
            .andExpect(header("apiKey", "test-key"))
            .andRespond(withSuccess(fixture, MediaType.APPLICATION_JSON));

        NvdCveResponse response = client.fetchPage(
            Instant.parse("2026-04-01T00:00:00Z"),
            Instant.parse("2026-04-29T00:00:00Z"),
            0, 2000);

        assertNotNull(response);
        server.verify();
    }
}
