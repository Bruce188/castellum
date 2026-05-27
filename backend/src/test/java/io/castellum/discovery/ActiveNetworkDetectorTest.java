package io.castellum.discovery;

import io.castellum.scan.ScanSizeGuard;
import io.castellum.scan.ScanScopeTooLargeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Fully synthetic unit tests for {@link ActiveNetworkDetector}.
 *
 * <p><strong>No test reads the host's real {@code /proc/net/route}.</strong>
 * No test enumerates real network interfaces. All fixtures are injected via
 * {@link ActiveNetworkDetector#parseRouteTable(List)} (pure function) or via a
 * temp-file + test-only constructor.
 */
class ActiveNetworkDetectorTest {

    // ---------------------------------------------------------------------------
    // Shared fixture data (little-endian hex, matching analysis §1 topology)
    // ---------------------------------------------------------------------------
    /** Fixture lines mirroring the WSL2/eth6 runtime topology from analysis §1. */
    private static final List<String> FULL_FIXTURE = List.of(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
        "eth6\t00000000\t0144A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0",
        "eth6\t0044A8C0\t00000000\t0001\t0\t0\t100\t00FCFFFF\t0\t0\t0",
        "eth0\t0000050A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0",
        "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0"
    );

    /** Fixture with no default-route row (neither Destination=0 nor Mask=0 combined). */
    private static final List<String> NO_DEFAULT_ROUTE_FIXTURE = List.of(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
        "eth0\t0000050A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0",
        "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0"
    );

    /**
     * Fixture where the default-route iface's connected net is a /16
     * ({@code Mask=0000FFFF}), triggering the /22 clamp.
     */
    private static final List<String> WIDE_PREFIX_FIXTURE = List.of(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0",
        "eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0"
    );

    /** Stub IP resolver that maps eth6 → 192.168.68.51, eth0 → 192.168.0.51. */
    private static final Function<String, Optional<Inet4Address>> STUB_IP_RESOLVER = iface -> {
        try {
            if ("eth6".equals(iface)) {
                return Optional.of((Inet4Address) InetAddress.getByName("192.168.68.51"));
            }
            if ("eth0".equals(iface)) {
                return Optional.of((Inet4Address) InetAddress.getByName("192.168.0.51"));
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
    };

    // ---------------------------------------------------------------------------
    // Case 1 — parseRouteTable selects eth6, derives 192.168.68.0/22
    // Pins little-endian byte-reversal: 0044A8C0 → 192.168.68.0, 00FCFFFF → /22
    // ---------------------------------------------------------------------------
    @Test
    void parseRouteTable_fullFixture_selectsEth6AndDerivesCorrectCidr() {
        Optional<ActiveNetworkDetector.ActiveNetwork> result =
            ActiveNetworkDetector.parseRouteTable(FULL_FIXTURE);

        assertThat(result).isPresent();
        ActiveNetworkDetector.ActiveNetwork net = result.get();
        assertThat(net.iface()).isEqualTo("eth6");
        assertThat(net.network()).isEqualTo("192.168.68.0");
        assertThat(net.prefix()).isEqualTo(22);
    }

    // ---------------------------------------------------------------------------
    // Case 2 — eth0 (NAT) and docker0 are excluded (no default route via them)
    // ---------------------------------------------------------------------------
    @Test
    void parseRouteTable_excludesNonDefaultRouteIfaces() {
        Optional<ActiveNetworkDetector.ActiveNetwork> result =
            ActiveNetworkDetector.parseRouteTable(FULL_FIXTURE);

        assertThat(result).isPresent();
        // Neither eth0 nor docker0 should be chosen
        assertThat(result.get().iface()).isNotIn("eth0", "docker0");
    }

    // ---------------------------------------------------------------------------
    // Case 3 — no default-route row → Optional.empty()
    // ---------------------------------------------------------------------------
    @Test
    void parseRouteTable_noDefaultRoute_returnsEmpty() {
        Optional<ActiveNetworkDetector.ActiveNetwork> result =
            ActiveNetworkDetector.parseRouteTable(NO_DEFAULT_ROUTE_FIXTURE);

        assertThat(result).isEmpty();
    }

    // ---------------------------------------------------------------------------
    // Case 4 — missing proc file → detect() returns Optional.empty()
    // ---------------------------------------------------------------------------
    @Test
    void detect_missingProcFile_returnsEmpty() {
        ActiveNetworkDetector detector = new ActiveNetworkDetector(
            "/tmp/definitely-missing-" + System.nanoTime(),
            STUB_IP_RESOLVER
        );
        Optional<ActiveNetworkDetector.ActiveNetwork> result = detector.detect();
        assertThat(result).isEmpty();
    }

    // ---------------------------------------------------------------------------
    // Case 5 — /16 connected net → clamped to ScanSizeGuard.MAX_ALLOWED_PREFIX with note
    // References the constant — does NOT hardcode 22.
    // ---------------------------------------------------------------------------
    @Test
    void detect_widePrefix_clampsToMaxAllowedPrefixWithNote(@TempDir Path tmp) throws Exception {
        Path fixture = tmp.resolve("route");
        Files.write(fixture, String.join("\n", WIDE_PREFIX_FIXTURE).getBytes(StandardCharsets.UTF_8));

        ActiveNetworkDetector detector = new ActiveNetworkDetector(fixture.toString(), STUB_IP_RESOLVER);
        Optional<ActiveNetworkDetector.ActiveNetwork> result = detector.detect();

        assertThat(result).isPresent();
        ActiveNetworkDetector.ActiveNetwork net = result.get();
        assertThat(net.prefix()).isEqualTo(ScanSizeGuard.MAX_ALLOWED_PREFIX);
        assertThat(net.note()).isNotNull().isNotBlank();
        assertThat(net.note()).contains("/" + ScanSizeGuard.MAX_ALLOWED_PREFIX);
    }

    // ---------------------------------------------------------------------------
    // Case 6 — ipAddress resolved via stubbed seam
    // ---------------------------------------------------------------------------
    @Test
    void detect_stubbedIpResolver_surfacesIpAddress(@TempDir Path tmp) throws Exception {
        Path fixture = tmp.resolve("route");
        Files.write(fixture, String.join("\n", FULL_FIXTURE).getBytes(StandardCharsets.UTF_8));

        ActiveNetworkDetector detector = new ActiveNetworkDetector(fixture.toString(), STUB_IP_RESOLVER);
        Optional<ActiveNetworkDetector.ActiveNetwork> result = detector.detect();

        assertThat(result).isPresent();
        assertThat(result.get().ipAddress()).isEqualTo("192.168.68.51");
    }

    // ---------------------------------------------------------------------------
    // Case 7 — derived cidr passes ScanSizeGuard.requireBoundedScope (invariant)
    // ---------------------------------------------------------------------------
    @Test
    void detect_derivedCidr_passesRequireBoundedScope(@TempDir Path tmp) throws Exception {
        Path fixture = tmp.resolve("route");
        Files.write(fixture, String.join("\n", FULL_FIXTURE).getBytes(StandardCharsets.UTF_8));

        ActiveNetworkDetector detector = new ActiveNetworkDetector(fixture.toString(), STUB_IP_RESOLVER);
        Optional<ActiveNetworkDetector.ActiveNetwork> result = detector.detect();

        assertThat(result).isPresent();
        // Should not throw ScanScopeTooLargeException
        assertThatCode(() -> ScanSizeGuard.requireBoundedScope(result.get().cidr()))
            .doesNotThrowAnyException();
    }
}
