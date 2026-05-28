package io.castellum.threatintel;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/**
 * Unit tests for {@link IntegrationProbeService}.
 *
 * Uses {@link MockRestServiceServer} bound to the service's {@code RestClient}
 * — no real network socket is opened.
 *
 * Cases:
 *   (a) upstream 200  → ProbeResult.reachable() == true
 *   (b) upstream 401  → ProbeResult.reachable() == true  (auth-gated host is still up)
 *   (c) connection refused (ResourceAccessException/ConnectException) → IntegrationProbeUnreachableException
 *   (d) read timeout (ResourceAccessException/SocketTimeoutException) → IntegrationProbeTimeoutException
 *   (e1) TAXII probe uses a discovery-style URI (contains /taxii2/ path segment)
 *   (e2) TAXII probe sends Accept: application/taxii+json;version=2.1
 *   (e3) MISP probe uses a different URI (contains /servers/getVersion or just root)
 */
@RestClientTest(IntegrationProbeService.class)
@TestPropertySource(properties = {
    "castellum.integration.probe.connect-timeout-ms=100",
    "castellum.integration.probe.read-timeout-ms=200"
})
class IntegrationProbeServiceTest {

    @Autowired
    IntegrationProbeService service;

    @Autowired
    MockRestServiceServer server;

    // -------------------------------------------------------------------------
    // (a) 200 response → reachable == true
    // -------------------------------------------------------------------------

    @Test
    void probe_taxii_200_isReachable() {
        server.expect(requestTo(org.hamcrest.Matchers.containsString("http://taxii.example.com")))
              .andExpect(method(GET))
              .andRespond(withSuccess());

        IntegrationProbeDto.ProbeResult result =
            service.probe("TAXII", "http://taxii.example.com", null);

        assertThat(result.reachable()).isTrue();
        server.verify();
    }

    // -------------------------------------------------------------------------
    // (b) 401 response → reachable == true (auth-gated server is still up)
    // -------------------------------------------------------------------------

    @Test
    void probe_taxii_401_isReachable() {
        server.expect(requestTo(org.hamcrest.Matchers.containsString("http://taxii.example.com")))
              .andExpect(method(GET))
              .andRespond(withUnauthorizedRequest());

        IntegrationProbeDto.ProbeResult result =
            service.probe("TAXII", "http://taxii.example.com", null);

        assertThat(result.reachable()).isTrue();
        server.verify();
    }

    // -------------------------------------------------------------------------
    // (c) Connection refused → IntegrationProbeUnreachableException
    // -------------------------------------------------------------------------

    @Test
    void probe_connectionRefused_throwsUnreachable() {
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
              .andRespond(withException(new ConnectException("Connection refused")));

        assertThatThrownBy(() -> service.probe("TAXII", "http://refused.example.com", null))
            .isInstanceOf(IntegrationProbeUnreachableException.class);
    }

    // -------------------------------------------------------------------------
    // (d) Read timeout → IntegrationProbeTimeoutException
    // -------------------------------------------------------------------------

    @Test
    void probe_readTimeout_throwsTimeout() {
        server.expect(requestTo(org.hamcrest.Matchers.anything()))
              .andRespond(withException(new SocketTimeoutException("Read timed out")));

        assertThatThrownBy(() -> service.probe("TAXII", "http://slow.example.com", null))
            .isInstanceOf(IntegrationProbeTimeoutException.class);
    }

    // -------------------------------------------------------------------------
    // (e1) TAXII probe URI includes the TAXII 2.1 discovery path
    // -------------------------------------------------------------------------

    @Test
    void probe_taxii_usesDiscoveryPath() {
        server.expect(requestTo(org.hamcrest.Matchers.containsString("/taxii2/")))
              .andExpect(method(GET))
              .andRespond(withSuccess());

        service.probe("TAXII", "http://taxii.example.com", null);
        server.verify();
    }

    // -------------------------------------------------------------------------
    // (e2) TAXII probe carries Accept: application/taxii+json;version=2.1
    // -------------------------------------------------------------------------

    @Test
    void probe_taxii_sendsAcceptHeader() {
        server.expect(requestTo(org.hamcrest.Matchers.containsString("taxii")))
              .andExpect(method(GET))
              .andExpect(header("Accept", org.hamcrest.Matchers.containsString("application/taxii+json")))
              .andRespond(withSuccess());

        service.probe("TAXII", "http://taxii.example.com", null);
        server.verify();
    }

    // -------------------------------------------------------------------------
    // (e3) MISP probe uses a different URI — does NOT go to /taxii2/
    // -------------------------------------------------------------------------

    @Test
    void probe_misp_usesMispPath() {
        // MISP probe should NOT use the TAXII discovery path
        server.expect(requestTo(org.hamcrest.Matchers.not(
                  org.hamcrest.Matchers.containsString("/taxii2/"))))
              .andExpect(method(GET))
              .andRespond(withSuccess());

        IntegrationProbeDto.ProbeResult result =
            service.probe("MISP", "http://misp.example.com", null);

        assertThat(result.reachable()).isTrue();
        server.verify();
    }

    // -------------------------------------------------------------------------
    // (e3-detail) MISP 200 is also reachable
    // -------------------------------------------------------------------------

    @Test
    void probe_misp_200_isReachable() {
        server.expect(requestTo(org.hamcrest.Matchers.containsString("http://misp.example.com")))
              .andExpect(method(GET))
              .andRespond(withSuccess());

        IntegrationProbeDto.ProbeResult result =
            service.probe("MISP", "http://misp.example.com", null);

        assertThat(result.reachable()).isTrue();
        server.verify();
    }

    // -------------------------------------------------------------------------
    // (e3-detail) MISP 401 is also reachable
    // -------------------------------------------------------------------------

    @Test
    void probe_misp_401_isReachable() {
        server.expect(requestTo(org.hamcrest.Matchers.containsString("http://misp.example.com")))
              .andExpect(method(GET))
              .andRespond(withUnauthorizedRequest());

        IntegrationProbeDto.ProbeResult result =
            service.probe("MISP", "http://misp.example.com", null);

        assertThat(result.reachable()).isTrue();
        server.verify();
    }
}
