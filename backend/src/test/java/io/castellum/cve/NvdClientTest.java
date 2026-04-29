package io.castellum.cve;

import io.castellum.cve.dto.NvdCveResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;

import java.io.IOException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

@RestClientTest(NvdClient.class)
@TestPropertySource(properties = {
    "castellum.nvd.base-url=https://test.nvd.example/rest/json/cves/2.0",
    "castellum.nvd.api-key=",
    "castellum.nvd.request-interval-millis=10"
})
class NvdClientTest {

    @Autowired
    NvdClient client;

    @Autowired
    MockRestServiceServer server;

    @Value("classpath:cve/nvd-page-sample.json")
    Resource fixture;

    private static final Instant START = Instant.parse("2026-04-01T00:00:00Z");
    private static final Instant END = Instant.parse("2026-04-29T00:00:00Z");

    @Test
    void fetchPage_buildsExpectedUri_andDeserializesResponse() throws Exception {
        server.expect(requestTo(org.hamcrest.Matchers.containsString("lastModStartDate=")))
            .andExpect(requestTo(org.hamcrest.Matchers.containsString("lastModEndDate=")))
            .andExpect(requestTo(org.hamcrest.Matchers.containsString("startIndex=0")))
            .andExpect(requestTo(org.hamcrest.Matchers.containsString("resultsPerPage=2000")))
            .andRespond(withSuccess(fixture, MediaType.APPLICATION_JSON));

        NvdCveResponse response = client.fetchPage(START, END, 0, 2000);

        assertNotNull(response);
        assertTrue(response.totalResults() > 0);
        server.verify();
    }

    @Test
    void fetchPage_omitsApiKeyHeaderWhenEmpty() throws Exception {
        server.expect(requestTo(org.hamcrest.Matchers.containsString("lastModStartDate=")))
            .andExpect(headerDoesNotExist("apiKey"))
            .andRespond(withSuccess(fixture, MediaType.APPLICATION_JSON));

        NvdCveResponse response = client.fetchPage(START, END, 0, 2000);
        assertNotNull(response);
        server.verify();
    }

    @Test
    void fetchPage_retriesOn403ThenSucceeds() throws Exception {
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
            .andRespond(withStatus(HttpStatus.FORBIDDEN));
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
            .andRespond(withSuccess(fixture, MediaType.APPLICATION_JSON));

        NvdCveResponse response = client.fetchPage(START, END, 0, 2000);
        assertNotNull(response);
        server.verify();
    }

    @Test
    void fetchPage_retriesOn503ThenSucceeds() throws Exception {
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
            .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
            .andRespond(withSuccess(fixture, MediaType.APPLICATION_JSON));

        NvdCveResponse response = client.fetchPage(START, END, 0, 2000);
        assertNotNull(response);
        server.verify();
    }

    @Test
    void fetchPage_givesUpAfter3RetriesAndThrows() {
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
            .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
            .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
            .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));

        assertThrows(IOException.class, () -> client.fetchPage(START, END, 0, 2000));
        server.verify();
    }

    @Test
    void fetchPage_respectsMinIntervalBetweenCalls() throws Exception {
        // Two mock responses
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
            .andRespond(withSuccess(fixture, MediaType.APPLICATION_JSON));
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
            .andRespond(withSuccess(fixture, MediaType.APPLICATION_JSON));

        long t1 = System.currentTimeMillis();
        client.fetchPage(START, END, 0, 2000);
        long t2 = System.currentTimeMillis();
        client.fetchPage(START, END, 0, 2000);
        long t3 = System.currentTimeMillis();

        // interval is 10ms — second call should be at least 10ms after the first call's pre-issue moment
        // (t2 is after first call returned, t3 is after second call returned)
        // The gap between first call finishing and second call finishing should be >= 10ms
        assertTrue((t3 - t1) >= 10, "Two calls should take at least intervalMillis total");
        server.verify();
    }
}
