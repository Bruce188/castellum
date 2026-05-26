package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

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
            // PUBLIC — verbatim spec line 367
            Arguments.of("8.8.8.8", DiscoveryScope.PUBLIC)
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
    void classify_ipv6Input_returnsPublic() {
        // Spec line 317: IPv6 falls through to PUBLIC as a safe default.
        assertThat(classifier.classify("::1")).isEqualTo(DiscoveryScope.PUBLIC);
    }
}
