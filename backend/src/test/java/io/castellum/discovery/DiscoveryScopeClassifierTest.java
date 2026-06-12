package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.InetAddress;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveryScopeClassifierTest {

    private final DiscoveryScopeClassifier classifier = new DiscoveryScopeClassifier();

    @ParameterizedTest
    @MethodSource("rfc1918AndNeighbors")
    void classify_returnsExpectedBucket(String ipv4, DiscoveryScope expected) {
        assertThat(classifier.classify(ipv4)).isEqualTo(expected);
    }

    static Stream<Arguments> rfc1918AndNeighbors() {
        return Stream.of(
            // HOME — verbatim spec lines 362-363
            Arguments.of("192.168.68.50", DiscoveryScope.HOME),
            Arguments.of("192.168.68.51", DiscoveryScope.HOME),   // host.docker.internal alias — IP wins
            // HOME — 10.0.0.0/8 RFC 1918 branch coverage
            Arguments.of("10.0.0.1", DiscoveryScope.HOME),
            // DOCKER_BRIDGE — verbatim spec lines 364-365
            Arguments.of("172.17.0.2", DiscoveryScope.DOCKER_BRIDGE),
            Arguments.of("172.18.0.3", DiscoveryScope.DOCKER_BRIDGE),
            // HOME — non-default Docker subnet falls through to RFC 1918 HOME, spec line 365-366
            Arguments.of("172.20.0.1", DiscoveryScope.HOME),
            // LINK_LOCAL — verbatim spec line 366
            Arguments.of("169.254.73.152", DiscoveryScope.LINK_LOCAL),
            // LOOPBACK — verbatim spec line 366
            Arguments.of("127.0.0.1", DiscoveryScope.LOOPBACK),
            // HOME — 100.64.0.0/10 RFC 6598 shared address space (CGNAT / mesh peers)
            Arguments.of("100.64.0.1", DiscoveryScope.HOME),
            Arguments.of("100.127.255.255", DiscoveryScope.HOME),
            // PUBLIC — just outside the CGNAT /10 on both sides
            Arguments.of("100.63.255.255", DiscoveryScope.PUBLIC),
            Arguments.of("100.128.0.0", DiscoveryScope.PUBLIC),
            // PUBLIC — verbatim spec line 367
            Arguments.of("8.8.8.8", DiscoveryScope.PUBLIC)
        );
    }

    @ParameterizedTest
    @MethodSource("ipv6Prefixes")
    void classify_ipv6_returnsExpectedBucket(String ipv6, DiscoveryScope expected) {
        assertThat(classifier.classify(ipv6)).isEqualTo(expected);
    }

    static Stream<Arguments> ipv6Prefixes() {
        return Stream.of(
            // LOOPBACK — ::1
            Arguments.of("::1", DiscoveryScope.LOOPBACK),
            // LINK_LOCAL — fe80::/10, case-insensitive
            Arguments.of("fe80::1", DiscoveryScope.LINK_LOCAL),
            Arguments.of("FE80::abcd", DiscoveryScope.LINK_LOCAL),
            Arguments.of("febf::1", DiscoveryScope.LINK_LOCAL),
            // HOME — fc00::/7 ULA = private LAN
            Arguments.of("fd00::1", DiscoveryScope.HOME),
            Arguments.of("fc00::1", DiscoveryScope.HOME),
            Arguments.of("fd12:3456::1", DiscoveryScope.HOME),
            // PUBLIC — global unicast
            Arguments.of("2001:4860:4860::8888", DiscoveryScope.PUBLIC),
            // PUBLIC — fec0 is outside fe80::/10; fe8 is a short (non-matching) hextet
            Arguments.of("fec0::1", DiscoveryScope.PUBLIC),
            Arguments.of("fe8::1", DiscoveryScope.PUBLIC)
        );
    }

    /**
     * Producer-form (uncompressed) IPv6 cases: ConnTableReader and PcapSniffer emit
     * InetAddress.getHostAddress() which may produce the fully-expanded form of an
     * address (e.g. "0:0:0:0:0:0:0:1" instead of "::1"). The classifier must
     * normalise before bucketing so these cases are NOT mis-classified as PUBLIC.
     */
    @ParameterizedTest
    @MethodSource("ipv6ProducerForm")
    void classify_ipv6ProducerForm_returnsExpectedBucket(String ipv6, DiscoveryScope expected) {
        assertThat(classifier.classify(ipv6)).isEqualTo(expected);
    }

    static Stream<Arguments> ipv6ProducerForm() throws Exception {
        return Stream.of(
            // Loopback — producer may emit the expanded form of ::1
            Arguments.of(InetAddress.getByName("::1").getHostAddress(), DiscoveryScope.LOOPBACK),
            // Link-local — producer may emit full form of fe80::1
            Arguments.of(InetAddress.getByName("fe80::1").getHostAddress(), DiscoveryScope.LINK_LOCAL),
            // ULA / HOME — producer may emit full form of fd00::1
            Arguments.of(InetAddress.getByName("fd00::1").getHostAddress(), DiscoveryScope.HOME),
            // Global unicast — must still classify PUBLIC
            Arguments.of(InetAddress.getByName("2001:4860:4860::8888").getHostAddress(), DiscoveryScope.PUBLIC)
        );
    }

    /**
     * IPv4-mapped IPv6 literals: InetAddress collapses {@code ::ffff:a.b.c.d} to a
     * plain Inet4Address (no colons), so the classifier must route the result through
     * the IPv4 chain — not crash in classifyIpv6, and not blanket-classify PUBLIC.
     * Malformed colon-bearing strings must fall back to the prefix chain unharmed.
     */
    @ParameterizedTest
    @MethodSource("ipv6V4MappedAndMalformed")
    void classify_ipv6V4MappedAndMalformed_returnsExpectedBucket(String ip, DiscoveryScope expected) {
        assertThat(classifier.classify(ip)).isEqualTo(expected);
    }

    static Stream<Arguments> ipv6V4MappedAndMalformed() {
        return Stream.of(
            // v4-mapped private — collapses to 192.168.1.1 → HOME via the IPv4 chain
            Arguments.of("::ffff:192.168.1.1", DiscoveryScope.HOME),
            // same address in expanded hex-group form
            Arguments.of("0:0:0:0:0:ffff:c0a8:101", DiscoveryScope.HOME),
            // v4-mapped loopback and public
            Arguments.of("::ffff:127.0.0.1", DiscoveryScope.LOOPBACK),
            Arguments.of("::ffff:8.8.8.8", DiscoveryScope.PUBLIC),
            // malformed but colon-bearing — falls back to the string prefix chain
            Arguments.of("fe80::zzzz", DiscoveryScope.LINK_LOCAL),
            Arguments.of("not:an:ip", DiscoveryScope.PUBLIC)
        );
    }

    @Test
    void classify_nullInput_returnsPublic() {
        assertThat(classifier.classify(null)).isEqualTo(DiscoveryScope.PUBLIC);
    }

    @Test
    void classify_blankInput_returnsPublic() {
        assertThat(classifier.classify("   ")).isEqualTo(DiscoveryScope.PUBLIC);
    }

    @Test
    void classify_ipv6Loopback_returnsLoopback() {
        // IPv6 is bucketed by prefix; ::1 must not pollute the External/Public zone.
        assertThat(classifier.classify("::1")).isEqualTo(DiscoveryScope.LOOPBACK);
    }
}
