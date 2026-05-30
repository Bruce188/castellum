package io.castellum.discovery.probe;

import io.castellum.discovery.DockerContainer.DockerNetworkAttachment;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SnmpBridgeMapper}.
 */
class SnmpBridgeMapperTest {

    private final SnmpBridgeMapper mapper = new SnmpBridgeMapper();

    private static SnmpClient.SnmpRow row(int idx, String descr, String name) {
        return new SnmpClient.SnmpRow(idx, descr, name, 131); // ifType=131 = IEEE 802.12
    }

    private static SnmpClient.SnmpAddr addr(String ip, int ifIndex) {
        return new SnmpClient.SnmpAddr(ip, ifIndex, "255.255.0.0");
    }

    // ---- docker0 maps to gateway-only, containerIp==null ----

    @Test
    void mapBridges_docker0_returnsGatewayOnly() {
        List<SnmpClient.SnmpRow> ifaces = List.of(row(1, "docker0", "docker0"));
        List<SnmpClient.SnmpAddr> addrs  = List.of(addr("172.17.0.1", 1));

        List<DockerNetworkAttachment> result = mapper.mapBridges(ifaces, addrs);

        assertThat(result).hasSize(1);
        DockerNetworkAttachment att = result.get(0);
        assertThat(att.networkName()).isEqualTo("snmp-bridge:docker0");
        assertThat(att.containerIp()).isNull();     // subnets-only
        assertThat(att.gatewayIp()).isEqualTo("172.17.0.1");
    }

    // ---- br-* maps to gateway-only ----

    @Test
    void mapBridges_brPrefix_returnsGateway() {
        List<SnmpClient.SnmpRow> ifaces = List.of(row(2, "br-abc123", "br-abc123"));
        List<SnmpClient.SnmpAddr> addrs  = List.of(addr("172.18.0.1", 2));

        List<DockerNetworkAttachment> result = mapper.mapBridges(ifaces, addrs);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).networkName()).isEqualTo("snmp-bridge:br-abc123");
        assertThat(result.get(0).containerIp()).isNull();
    }

    // ---- eth0 excluded ----

    @Test
    void mapBridges_eth0_excluded() {
        List<SnmpClient.SnmpRow> ifaces = List.of(row(3, "eth0", "eth0"));
        List<SnmpClient.SnmpAddr> addrs  = List.of(addr("192.168.1.1", 3));

        List<DockerNetworkAttachment> result = mapper.mapBridges(ifaces, addrs);
        assertThat(result).isEmpty();
    }

    // ---- malformed row (blank name) skipped ----

    @Test
    void mapBridges_malformedBlankName_skipped() {
        List<SnmpClient.SnmpRow> ifaces = List.of(
            new SnmpClient.SnmpRow(4, "", "", 131),   // blank descr + name
            row(5, "docker0", "docker0"));
        List<SnmpClient.SnmpAddr> addrs  = List.of(addr("172.17.0.1", 5));

        List<DockerNetworkAttachment> result = mapper.mapBridges(ifaces, addrs);
        // Only docker0 row should appear
        assertThat(result).hasSize(1);
        assertThat(result.get(0).networkName()).contains("docker0");
    }

    // ---- no IP for bridge → skipped ----

    @Test
    void mapBridges_noIpForBridge_skipped() {
        List<SnmpClient.SnmpRow> ifaces = List.of(row(6, "docker0", "docker0"));
        List<SnmpClient.SnmpAddr> addrs  = List.of(); // no address rows

        List<DockerNetworkAttachment> result = mapper.mapBridges(ifaces, addrs);
        assertThat(result).isEmpty();
    }

    // ---- veth* maps to gateway-only ----

    @Test
    void mapBridges_vethPrefix_returnsGateway() {
        List<SnmpClient.SnmpRow> ifaces = List.of(row(7, "veth0a1b2c", "veth0a1b2c"));
        List<SnmpClient.SnmpAddr> addrs  = List.of(addr("172.19.0.1", 7));

        List<DockerNetworkAttachment> result = mapper.mapBridges(ifaces, addrs);
        assertThat(result).hasSize(1);
        assertThat(result.get(0).containerIp()).isNull();
    }

    // ---- empty input ----

    @Test
    void mapBridges_emptyInput_returnsEmpty() {
        assertThat(mapper.mapBridges(List.of(), List.of())).isEmpty();
        assertThat(mapper.mapBridges(null, List.of())).isEmpty();
    }
}
