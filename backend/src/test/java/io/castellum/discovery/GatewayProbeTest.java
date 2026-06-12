package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fully synthetic unit tests for {@link GatewayProbe}.
 *
 * <p><strong>No test reads the host's real {@code /proc/net/route}.</strong> Fixtures
 * mirror {@link ActiveNetworkDetectorTest}: tab-separated rows with little-endian hex
 * fields ({@code 0144A8C0} → 192.168.68.1).
 */
class GatewayProbeTest {

    @TempDir
    Path tempDir;

    private static final String ROUTE_HEADER =
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT";

    private GatewayProbe probeWith(String... lines) throws IOException {
        Path route = tempDir.resolve("route");
        Files.writeString(route, String.join("\n", lines) + "\n");
        return new GatewayProbe(route.toString());
    }

    @Test
    void probe_defaultRoutePresent_returnsSingleGatewayNeighbor() throws IOException {
        GatewayProbe probe = probeWith(
            ROUTE_HEADER,
            "eth6\t00000000\t0144A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0",
            "eth6\t0044A8C0\t00000000\t0001\t0\t0\t100\t00FCFFFF\t0\t0\t0",
            "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0");

        List<DiscoveredNeighbor> result = probe.probe();

        assertThat(result).hasSize(1);
        DiscoveredNeighbor gw = result.get(0);
        assertThat(gw.ipAddress()).isEqualTo("192.168.68.1");
        assertThat(gw.iface()).isEqualTo("eth6");
        assertThat(gw.macAddress()).isNull();
        assertThat(gw.hostname()).isNull();
    }

    @Test
    void probe_noDefaultRoute_returnsEmpty() throws IOException {
        // Only on-link rows (Gateway=0) — no Destination=0/Mask=0/Gateway≠0 row.
        GatewayProbe probe = probeWith(
            ROUTE_HEADER,
            "eth0\t0000050A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0",
            "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0");

        assertThat(probe.probe()).isEmpty();
    }

    @Test
    void probe_missingRouteFile_returnsEmpty() {
        GatewayProbe probe = new GatewayProbe(tempDir.resolve("no-such-route").toString());

        assertThat(probe.probe()).isEmpty();
    }

    @Test
    void probe_malformedGatewayHex_skipsRowAndKeepsLaterValidDefaultRoute() throws IOException {
        // Row 1: default-route shape but non-hex gateway — must be skipped, not thrown.
        // Row 2: valid default route — still found.
        GatewayProbe probe = probeWith(
            ROUTE_HEADER,
            "eth6\t00000000\tZZZZZZZZ\t0003\t0\t0\t100\t00000000\t0\t0\t0",
            "eth6\t00000000\t0144A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0");

        List<DiscoveredNeighbor> result = probe.probe();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.68.1");
    }

    @Test
    void probe_onlyMalformedDefaultRoutes_returnsEmptyWithoutThrowing() throws IOException {
        // Non-hex and wrong-length gateway fields — both skipped, empty result.
        GatewayProbe probe = probeWith(
            ROUTE_HEADER,
            "eth6\t00000000\tZZZZZZZZ\t0003\t0\t0\t100\t00000000\t0\t0\t0",
            "eth6\t00000000\t0144A8C\t0003\t0\t0\t100\t00000000\t0\t0\t0");

        assertThat(probe.probe()).isEmpty();
    }
}
