package io.castellum.threatintel;

import io.castellum.threatintel.misp.MispClient;
import io.castellum.threatintel.stix.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@RestClientTest(MispClient.class)
@TestPropertySource(properties = {
    "castellum.misp.base-url=http://misp.example.com",
    "castellum.misp.api-key=test-ac3-key",
    "castellum.misp.distribution=0",
    "castellum.misp.threat-level-id=2",
    "castellum.misp.backoff-base-millis=10"
})
class AcceptanceMispPushTest {

    @Autowired MispClient client;
    @Autowired MockRestServiceServer server;

    @Test
    void ac3_mispPushAcceptedSurrogate() throws Exception {
        server.expect(requestTo("http://misp.example.com/events/add"))
            .andRespond(withSuccess("{\"Event\":{\"id\":\"42\"}}", MediaType.APPLICATION_JSON));
        var resp = client.push(sampleBundle());
        assertThat(resp.eventId()).isEqualTo("42");
        server.verify();
    }

    private StixBundle sampleBundle() {
        var now = OffsetDateTime.now();
        var vuln = new StixVulnerability("vulnerability", "2.1",
            StixIds.forCve("CVE-2026-AC3"), now, now, StixIds.IDENTITY_ID,
            "CVE-2026-AC3", "AC3 test CVE",
            List.of(new ExternalReference("cve", "CVE-2026-AC3")));
        var infra = new StixInfrastructure("infrastructure", "2.1",
            StixIds.forDevice("10.0.0.99"), now, now, StixIds.IDENTITY_ID,
            "ac3-device", List.of("unknown"),
            Map.of("x_castellum", Map.of("ip_address", "10.0.0.99")));
        return StixBundle.of(StixIds.forBundle(), List.of(vuln, infra));
    }
}
