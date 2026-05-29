package io.castellum.discovery.probe;

import io.castellum.discovery.DockerContainer;
import io.castellum.discovery.DockerInspectParser;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DockerApiNetworkMapper} and parser-reuse via {@link DockerInspectParser}.
 */
class DockerApiNetworkMapperTest {

    private static final DockerApiNetworkMapper mapper = new DockerApiNetworkMapper();
    private static final DockerInspectParser inspectParser = new DockerInspectParser();

    private static String fixture(String name) throws IOException {
        try (InputStream in = DockerApiNetworkMapperTest.class.getResourceAsStream("/docker/" + name)) {
            if (in == null) throw new IOException("fixture /docker/" + name + " not found");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // (1) api-networks.json → mapped names, gateways, subnets
    @Test
    void mapNetworks_fixtureJson_extractsGatewaysAndNames() throws Exception {
        String json = fixture("api-networks.json");
        List<DockerContainer.DockerNetworkAttachment> nets = mapper.mapNetworks(json);

        assertThat(nets).hasSize(2);

        // First network: pingpay_default, gateway 172.18.0.1
        DockerContainer.DockerNetworkAttachment first = nets.stream()
            .filter(n -> "pingpay_default".equals(n.networkName()))
            .findFirst()
            .orElseThrow();
        assertThat(first.gatewayIp()).isEqualTo("172.18.0.1");

        // Second network: supabase_network_pingpay, gateway 172.19.0.1
        DockerContainer.DockerNetworkAttachment second = nets.stream()
            .filter(n -> "supabase_network_pingpay".equals(n.networkName()))
            .findFirst()
            .orElseThrow();
        assertThat(second.gatewayIp()).isEqualTo("172.19.0.1");
    }

    // (2) blank / null → empty list
    @Test
    void mapNetworks_blank_returnsEmpty() {
        assertThat(mapper.mapNetworks("")).isEmpty();
        assertThat(mapper.mapNetworks("   ")).isEmpty();
        assertThat(mapper.mapNetworks(null)).isEmpty();
    }

    // (3) malformed JSON → IllegalArgumentException
    @Test
    void mapNetworks_malformedJson_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> mapper.mapNetworks("{not json"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    // (4) non-array JSON → empty list (not an exception)
    @Test
    void mapNetworks_nonArray_returnsEmpty() {
        assertThat(mapper.mapNetworks("{}")).isEmpty();
    }

    // (5) Parser-reuse proof: api-container-inspect.json feeds through DockerInspectParser
    //     to produce a DockerContainer with expected IP and gateway.
    @Test
    void inspectParser_reuse_apiContainerInspectFixture() throws Exception {
        String json = fixture("api-container-inspect.json");
        List<DockerContainer> containers = inspectParser.parse(json);

        assertThat(containers).hasSize(1);
        DockerContainer c = containers.get(0);
        assertThat(c.name()).isEqualTo("pingpay-frontend");

        DockerContainer.DockerNetworkAttachment primary = c.primaryNetwork();
        assertThat(primary).isNotNull();
        assertThat(primary.containerIp()).isEqualTo("172.18.0.4");
        assertThat(primary.gatewayIp()).isEqualTo("172.18.0.1");

        // Publishes host port 1071
        assertThat(c.publishesHostPort()).isTrue();
    }
}
