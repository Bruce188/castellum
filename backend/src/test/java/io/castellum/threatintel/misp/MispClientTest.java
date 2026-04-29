package io.castellum.threatintel.misp;

import io.castellum.threatintel.stix.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

@RestClientTest(MispClient.class)
@TestPropertySource(properties = {
    "castellum.misp.base-url=http://misp.example.com",
    "castellum.misp.api-key=test-api-key-123",
    "castellum.misp.distribution=0",
    "castellum.misp.threat-level-id=2",
    "castellum.misp.backoff-base-millis=10"
})
class MispClientTest {

    @Autowired MispClient client;
    @Autowired MockRestServiceServer server;

    @Test
    void push_returns200_andParsesEventId() throws Exception {
        server.expect(requestTo("http://misp.example.com/events/add"))
            .andExpect(method(org.springframework.http.HttpMethod.POST))
            .andExpect(jsonPath("$.Event.distribution").value("0"))
            .andExpect(jsonPath("$.Event.threat_level_id").value("2"))
            .andExpect(jsonPath("$.Event.Attribute[?(@.type=='vulnerability')].value")
                .value(org.hamcrest.Matchers.hasItem("CVE-2026-0001")))
            .andExpect(jsonPath("$.Event.Attribute[?(@.type=='ip-dst')].value")
                .value(org.hamcrest.Matchers.hasItem("10.0.0.5")))
            .andRespond(withSuccess("{\"Event\":{\"id\":\"42\"}}", MediaType.APPLICATION_JSON));
        var bundle = sampleBundle();
        var resp = client.push(bundle);
        assertThat(resp.eventId()).isEqualTo("42");
        server.verify();
    }

    @Test
    void push_authHeaderRawApiKey_noBearer() throws Exception {
        server.expect(requestTo("http://misp.example.com/events/add"))
            .andExpect(header("Authorization", "test-api-key-123"))
            .andRespond(withSuccess("{\"Event\":{\"id\":\"1\"}}", MediaType.APPLICATION_JSON));
        client.push(sampleBundle());
        server.verify();
    }

    @Test
    void push_retriesOn5xx_thenSucceeds() throws Exception {
        server.expect(requestTo("http://misp.example.com/events/add"))
            .andRespond(withServerError());
        server.expect(requestTo("http://misp.example.com/events/add"))
            .andRespond(withSuccess("{\"Event\":{\"id\":\"99\"}}", MediaType.APPLICATION_JSON));
        var resp = client.push(sampleBundle());
        assertThat(resp.eventId()).isEqualTo("99");
        server.verify();
    }

    @Test
    void push_failsAfter3_5xx() {
        for (int i = 0; i < 3; i++) {
            server.expect(requestTo("http://misp.example.com/events/add"))
                .andRespond(withServerError());
        }
        assertThatThrownBy(() -> client.push(sampleBundle()))
            .isInstanceOf(IOException.class);
        server.verify();
    }

    private StixBundle sampleBundle() {
        var now = OffsetDateTime.now();
        var vuln = new StixVulnerability("vulnerability", "2.1",
            StixIds.forCve("CVE-2026-0001"), now, now, StixIds.IDENTITY_ID,
            "CVE-2026-0001", "Test CVE",
            List.of(new ExternalReference("cve", "CVE-2026-0001")));
        var infra = new StixInfrastructure("infrastructure", "2.1",
            StixIds.forDevice("10.0.0.5"), now, now, StixIds.IDENTITY_ID,
            "plc-01", List.of("unknown"),
            Map.of("x_castellum", Map.of("ip_address", "10.0.0.5")));
        return StixBundle.of(StixIds.forBundle(), List.of(vuln, infra));
    }
}
