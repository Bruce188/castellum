package io.castellum.threatintel;

import io.castellum.threatintel.taxii.TaxiiClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

@RestClientTest(TaxiiClient.class)
@TestPropertySource(properties = {
    "castellum.taxii.base-url=http://taxii.example.com",
    "castellum.taxii.collection-id=ac2",
    "castellum.taxii.username=admin",
    "castellum.taxii.password=Password0",
    "castellum.taxii.backoff-base-millis=10"
})
class AcceptanceTaxiiPushTest {

    @Autowired TaxiiClient client;
    @Autowired MockRestServiceServer server;

    @Test
    void ac2_taxiiPushReturns201Surrogate() throws Exception {
        server.expect(requestTo("http://taxii.example.com/collections/ac2/objects/"))
            .andRespond(withStatus(org.springframework.http.HttpStatus.CREATED));
        int code = client.push("{\"type\":\"bundle\",\"id\":\"bundle--ac2\"}");
        assertThat(code).isEqualTo(201);
        server.verify();
    }
}
