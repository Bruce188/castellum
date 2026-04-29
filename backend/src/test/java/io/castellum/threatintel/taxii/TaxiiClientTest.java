package io.castellum.threatintel.taxii;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

@RestClientTest(TaxiiClient.class)
@TestPropertySource(properties = {
    "castellum.taxii.base-url=http://taxii.example.com",
    "castellum.taxii.collection-id=test-collection",
    "castellum.taxii.username=admin",
    "castellum.taxii.password=Password0",
    "castellum.taxii.backoff-base-millis=10"
})
class TaxiiClientTest {

    @Autowired TaxiiClient client;
    @Autowired MockRestServiceServer server;

    @Test
    void push_returns201_onSuccess() throws Exception {
        server.expect(requestTo("http://taxii.example.com/collections/test-collection/objects/"))
            .andExpect(method(org.springframework.http.HttpMethod.POST))
            .andExpect(header("Content-Type", "application/taxii+json;version=2.1"))
            .andExpect(header("Authorization", "Basic YWRtaW46UGFzc3dvcmQw")) // base64("admin:Password0")
            .andExpect(content().string("{\"type\":\"bundle\"}"))
            .andRespond(withStatus(org.springframework.http.HttpStatus.CREATED));
        int code = client.push("{\"type\":\"bundle\"}");
        assertThat(code).isEqualTo(201);
        server.verify();
    }

    @Test
    void push_retriesOn5xx_thenSucceeds() throws Exception {
        server.expect(requestTo("http://taxii.example.com/collections/test-collection/objects/"))
            .andRespond(withServerError());
        server.expect(requestTo("http://taxii.example.com/collections/test-collection/objects/"))
            .andRespond(withStatus(org.springframework.http.HttpStatus.CREATED));
        int code = client.push("{\"type\":\"bundle\"}");
        assertThat(code).isEqualTo(201);
        server.verify();
    }

    @Test
    void push_failsAfter3_5xx() {
        server.expect(requestTo("http://taxii.example.com/collections/test-collection/objects/"))
            .andRespond(withServerError());
        server.expect(requestTo("http://taxii.example.com/collections/test-collection/objects/"))
            .andRespond(withServerError());
        server.expect(requestTo("http://taxii.example.com/collections/test-collection/objects/"))
            .andRespond(withServerError());
        assertThatThrownBy(() -> client.push("{\"type\":\"bundle\"}"))
            .isInstanceOf(IOException.class);
        server.verify();
    }
}
