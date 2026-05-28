package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Pure unit tests for {@link DockerInspectParser}. No Spring context required.
 *
 * <p>The reference fixture {@code /docker/inspect-reference.json} is hand-authored to the
 * standard {@code docker inspect} schema and models the live reference stack:
 * pingpay (frontend/backend published, db internal) on {@code 172.18.x} and supabase
 * (kong/studio/db published, pg_meta/storage internal) on {@code 172.19.x}.
 */
class DockerInspectParserTest {

    private final DockerInspectParser parser = new DockerInspectParser();

    private static String fixture(String name) throws IOException {
        try (InputStream in = DockerInspectParserTest.class.getResourceAsStream("/docker/" + name)) {
            assertNotNull(in, "fixture /docker/" + name + " must be on the test classpath");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static DockerContainer byName(List<DockerContainer> containers, String name) {
        Optional<DockerContainer> found =
            containers.stream().filter(c -> c.name().equals(name)).findFirst();
        assertThat(found).as("expected a container named %s", name).isPresent();
        return found.get();
    }

    // -----------------------------------------------------------------------
    // Reference fixture: count + name extraction
    // -----------------------------------------------------------------------

    @Test
    void parse_referenceFixture_extractsAllContainers() throws IOException {
        List<DockerContainer> containers = parser.parse(fixture("inspect-reference.json"));
        assertThat(containers).hasSize(8);
        assertThat(containers).extracting(DockerContainer::name)
            .containsExactlyInAnyOrder(
                "pingpay-frontend", "pingpay-backend", "pingpay-db",
                "supabase_kong_pingpay", "supabase_studio_pingpay", "supabase_db_pingpay",
                "supabase_pg_meta_pingpay", "supabase_storage_pingpay");
    }

    @Test
    void parse_stripsLeadingSlashFromName() throws IOException {
        DockerContainer c = byName(parser.parse(fixture("inspect-reference.json")), "pingpay-frontend");
        assertThat(c.name()).doesNotStartWith("/");
    }

    // -----------------------------------------------------------------------
    // Network + IP + gateway extraction
    // -----------------------------------------------------------------------

    @Test
    void parse_extractsPrimaryNetworkIpAndGateway() throws IOException {
        DockerContainer frontend = byName(parser.parse(fixture("inspect-reference.json")), "pingpay-frontend");
        DockerContainer.DockerNetworkAttachment primary = frontend.primaryNetwork();
        assertThat(primary).isNotNull();
        assertThat(primary.networkName()).isEqualTo("pingpay_default");
        assertThat(primary.containerIp()).isEqualTo("172.18.0.4");
        assertThat(primary.gatewayIp()).isEqualTo("172.18.0.1");
    }

    @Test
    void parse_distinctSubnetsPerComposeStack() throws IOException {
        List<DockerContainer> containers = parser.parse(fixture("inspect-reference.json"));
        // pingpay stack on 172.18.x with gateway .1
        assertThat(byName(containers, "pingpay-db").primaryNetwork().gatewayIp()).isEqualTo("172.18.0.1");
        // supabase stack on a DISTINCT subnet 172.19.x with its own gateway .1
        assertThat(byName(containers, "supabase_db_pingpay").primaryNetwork().gatewayIp()).isEqualTo("172.19.0.1");
    }

    // -----------------------------------------------------------------------
    // Published-port detection (drives DOCKER_BRIDGE vs HOME scope downstream)
    // -----------------------------------------------------------------------

    @Test
    void parse_publishedPort_flaggedTrue() throws IOException {
        List<DockerContainer> containers = parser.parse(fixture("inspect-reference.json"));
        // frontend publishes 80->1071, backend 3000->3000
        assertThat(byName(containers, "pingpay-frontend").publishesHostPort()).isTrue();
        assertThat(byName(containers, "pingpay-backend").publishesHostPort()).isTrue();
        // supabase kong/studio/db all publish
        assertThat(byName(containers, "supabase_kong_pingpay").publishesHostPort()).isTrue();
        assertThat(byName(containers, "supabase_studio_pingpay").publishesHostPort()).isTrue();
        assertThat(byName(containers, "supabase_db_pingpay").publishesHostPort()).isTrue();
    }

    @Test
    void parse_internalOnlyPort_flaggedFalse() throws IOException {
        List<DockerContainer> containers = parser.parse(fixture("inspect-reference.json"));
        // db exposes 3306/tcp with a null binding (internal-only)
        assertThat(byName(containers, "pingpay-db").publishesHostPort()).isFalse();
        // pg_meta exposes 8080/tcp null; storage has an empty Ports object
        assertThat(byName(containers, "supabase_pg_meta_pingpay").publishesHostPort()).isFalse();
        assertThat(byName(containers, "supabase_storage_pingpay").publishesHostPort()).isFalse();
    }

    // -----------------------------------------------------------------------
    // Defensive: malformed / empty / multi-homed / no-IP edge cases
    // -----------------------------------------------------------------------

    @Test
    void parse_empty_returnsEmptyList() {
        assertThat(parser.parse("")).isEmpty();
        assertThat(parser.parse("   ")).isEmpty();
        assertThat(parser.parse(null)).isEmpty();
    }

    @Test
    void parse_emptyArray_returnsEmptyList() {
        assertThat(parser.parse("[]")).isEmpty();
    }

    @Test
    void parse_nonArrayJson_returnsEmptyList() {
        // docker inspect always emits an array; a bare object is not valid input shape.
        assertThat(parser.parse("{\"Name\":\"/x\"}")).isEmpty();
    }

    @Test
    void parse_malformedJson_throwsIllegalArgument() {
        assertThatThrownBy(() -> parser.parse("[ {\"Name\": "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("malformed docker inspect JSON");
    }

    @Test
    void parse_containerWithNoUsableIp_primaryNetworkNull() {
        // host-network containers report an empty Networks map / blank IPs.
        String json = """
            [
              {
                "Id": "deadbeef",
                "Name": "/host-net-app",
                "NetworkSettings": { "Ports": {}, "Networks": { "host": { "IPAddress": "", "Gateway": "" } } }
              }
            ]
            """;
        List<DockerContainer> containers = parser.parse(json);
        assertThat(containers).hasSize(1);
        assertThat(containers.get(0).primaryNetwork()).isNull();
    }

    @Test
    void parse_multiHomedContainer_picksFirstAttachmentWithIp() {
        String json = """
            [
              {
                "Id": "multi",
                "Name": "/multi-homed",
                "NetworkSettings": {
                  "Ports": {},
                  "Networks": {
                    "frontend_net": { "IPAddress": "172.20.0.2", "Gateway": "172.20.0.1" },
                    "backend_net":  { "IPAddress": "172.21.0.2", "Gateway": "172.21.0.1" }
                  }
                }
              }
            ]
            """;
        DockerContainer c = parser.parse(json).get(0);
        assertThat(c.networks()).hasSize(2);
        // First attachment with a usable IP wins (deterministic primary selection).
        assertThat(c.primaryNetwork().containerIp()).isEqualTo("172.20.0.2");
    }

    @Test
    void parse_unnamedElement_skipped() {
        String json = "[ { \"Id\": \"x\", \"NetworkSettings\": { \"Networks\": {} } } ]";
        assertThat(parser.parse(json)).isEmpty();
    }
}
