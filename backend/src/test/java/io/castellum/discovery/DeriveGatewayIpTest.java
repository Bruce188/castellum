package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Direct unit test for {@link DockerDiscoveryService#deriveGatewayIp(String)}.
 *
 * <p><b>RED-PHASE NOTE — compile-time red:</b> {@code deriveGatewayIp} is currently
 * {@code private}. This class will NOT compile until the implementer relaxes the method to
 * package-private (default access). The compile error is the expected red for test 9.
 *
 * <p>Once visibility is relaxed, the test on {@code "10.0.0.255/24"} will additionally
 * FAIL at runtime because incrementing octet 255 produces "10.0.0.256" (an invalid IP)
 * rather than {@code null}. Both the compile error and the assertion failure are
 * intentional reds for the implementer to fix.
 */
class DeriveGatewayIpTest {

    /**
     * Happy path: standard network address yields the .1 gateway.
     * Edge case: network address whose last octet is 255 must return null
     * rather than the invalid "10.0.0.256".
     */
    @Test
    void deriveGatewayIp_networkAddressEndsIn255_returnsNull() {
        // Happy path: well-formed subnet → .1 gateway
        assertThat(DockerDiscoveryService.deriveGatewayIp("172.17.0.0/16"))
            .as("standard network address must yield the .1 gateway")
            .isEqualTo("172.17.0.1");

        // Edge case: last octet is 255; incrementing to 256 is invalid — must return null
        assertThat(DockerDiscoveryService.deriveGatewayIp("10.0.0.255/24"))
            .as("subnet with last-octet 255 must return null (would produce invalid '10.0.0.256')")
            .isNull();
    }
}
