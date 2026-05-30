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

    // -----------------------------------------------------------------------
    // Config.Image + exposed-port extraction (drives image→CPE service derivation)
    // -----------------------------------------------------------------------

    @Test
    void parse_extractsImageFromConfig() throws IOException {
        List<DockerContainer> containers = parser.parse(fixture("inspect-reference.json"));
        assertThat(byName(containers, "pingpay-db").image()).isEqualTo("postgres:15.6");
        assertThat(byName(containers, "pingpay-frontend").image()).isEqualTo("nginx:1.27.0");
        assertThat(byName(containers, "supabase_db_pingpay").image())
            .isEqualTo("public.ecr.aws/supabase/postgres:15.1.0.147");
    }

    @Test
    void parse_extractsExposedPortsWithProtocol() throws IOException {
        List<DockerContainer> containers = parser.parse(fixture("inspect-reference.json"));
        // pingpay-db exposes 3306/tcp (internal-only — still listed as an exposed port)
        DockerContainer db = byName(containers, "pingpay-db");
        assertThat(db.exposedPorts()).containsExactly(new DockerContainer.ExposedPort(3306, "tcp"));
        assertThat(db.primaryPort()).isEqualTo(new DockerContainer.ExposedPort(3306, "tcp"));
        // storage exposes none (empty Ports object)
        DockerContainer storage = byName(containers, "supabase_storage_pingpay");
        assertThat(storage.exposedPorts()).isEmpty();
        assertThat(storage.primaryPort()).isNull();
    }

    @Test
    void parse_primaryPort_picksLowestExposed() {
        String json = """
            [
              {
                "Id": "x", "Name": "/multi-port",
                "NetworkSettings": {
                  "Ports": { "8443/tcp": null, "443/tcp": null, "80/tcp": [ { "HostPort": "80" } ] },
                  "Networks": { "n": { "IPAddress": "172.30.0.2", "Gateway": "172.30.0.1" } }
                }
              }
            ]
            """;
        DockerContainer c = parser.parse(json).get(0);
        assertThat(c.exposedPorts()).hasSize(3);
        assertThat(c.primaryPort().port()).isEqualTo(80);
    }

    @Test
    void parse_missingConfig_imageNull() {
        String json = """
            [
              {
                "Id": "x", "Name": "/no-config",
                "NetworkSettings": { "Ports": {}, "Networks": { "n": { "IPAddress": "172.31.0.2", "Gateway": "172.31.0.1" } } }
              }
            ]
            """;
        assertThat(parser.parse(json).get(0).image()).isNull();
    }

    // -----------------------------------------------------------------------
    // Task 1.2 — parseNetworkInspect: BridgeNetworkInfo parsing
    // -----------------------------------------------------------------------

    @Test
    void parseNetworkInspect_iccOn_readsMembersAndSubnet() throws IOException {
        // LOCKS invariant 2 — actual enable_icc=true read, not assumed
        DockerInspectParser.BridgeNetworkInfo info =
            parser.parseNetworkInspect(fixture("network-inspect-bridge-icc-on.json"));

        assertThat(info.isDefaultBridge()).isTrue();
        assertThat(info.iccEnabled()).isTrue();
        assertThat(info.subnet()).isEqualTo("172.17.0.0/16");
        assertThat(info.members()).hasSizeGreaterThanOrEqualTo(2);
        // CIDR suffix must be stripped from every member IP
        for (DockerInspectParser.Member m : info.members()) {
            assertThat(m.ipv4()).as("CIDR suffix must be stripped").doesNotContain("/");
            assertThat(m.ipv4()).startsWith("172.17.0.");
        }
    }

    @Test
    void parseNetworkInspect_iccOff_iccEnabledFalse() throws IOException {
        // LOCKS invariant 2 — the false case is actually parsed (planner's guard)
        DockerInspectParser.BridgeNetworkInfo info =
            parser.parseNetworkInspect(fixture("network-inspect-bridge-icc-off.json"));

        assertThat(info.isDefaultBridge()).isTrue();
        assertThat(info.iccEnabled()).isFalse();
    }

    @Test
    void parseNetworkInspect_singleMember_oneMember() throws IOException {
        DockerInspectParser.BridgeNetworkInfo info =
            parser.parseNetworkInspect(fixture("network-inspect-bridge-single.json"));

        assertThat(info.isDefaultBridge()).isTrue();
        assertThat(info.members()).hasSize(1);
    }

    @Test
    void parseNetworkInspect_emptyContainers_zeroMembers() throws IOException {
        DockerInspectParser.BridgeNetworkInfo info =
            parser.parseNetworkInspect(fixture("network-inspect-bridge-empty.json"));

        assertThat(info.isDefaultBridge()).isTrue();
        assertThat(info.members()).isEmpty();
    }

    @Test
    void parseNetworkInspect_notDefaultBridge_isDefaultBridgeFalse() {
        // LOCKS invariant 4 — Name alone is NOT sufficient; default_bridge option must be "true"
        String json = """
            [
              {
                "Name": "bridge",
                "Options": {
                  "com.docker.network.bridge.default_bridge": "false"
                },
                "IPAM": { "Config": [] },
                "Containers": {}
              }
            ]
            """;
        DockerInspectParser.BridgeNetworkInfo info = parser.parseNetworkInspect(json);
        assertThat(info.isDefaultBridge()).isFalse();
    }

    @Test
    void parseNetworkInspect_defaultBridgeOptionAbsent_isDefaultBridgeFalse() {
        // LOCKS invariant 4 — absent default_bridge option ⇒ not authoritative default bridge
        String json = """
            [
              {
                "Name": "bridge",
                "Options": {},
                "IPAM": { "Config": [] },
                "Containers": {}
              }
            ]
            """;
        DockerInspectParser.BridgeNetworkInfo info = parser.parseNetworkInspect(json);
        assertThat(info.isDefaultBridge()).isFalse();
    }

    @Test
    void parseNetworkInspect_blankOrEmptyArray_sentinel() {
        // null, blank, and "[]" must all return isDefaultBridge=false without throwing
        assertThat(parser.parseNetworkInspect(null).isDefaultBridge()).isFalse();
        assertThat(parser.parseNetworkInspect(null).members()).isEmpty();
        assertThat(parser.parseNetworkInspect("").isDefaultBridge()).isFalse();
        assertThat(parser.parseNetworkInspect("[]").isDefaultBridge()).isFalse();
        assertThat(parser.parseNetworkInspect("[]").members()).isEmpty();
    }
}
