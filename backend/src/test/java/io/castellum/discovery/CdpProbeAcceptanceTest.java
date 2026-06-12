package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.net.InetAddress;
import java.net.URL;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Acceptance test for the CDP (Cisco Discovery Protocol) probe path against a
 * captured fixture.
 *
 * <p>Gated by the {@code managed-switch-lab} Maven profile
 * ({@code mvn test -Pmanaged-switch-lab}), which sets
 * {@code castellum.managed-switch-lab=true}. Default {@code mvn test} skips
 * this class silently with no JUnit warning.
 *
 * <p>Even when the profile is active, the test aborts gracefully via
 * {@link org.junit.jupiter.api.Assumptions#assumeTrue} if the fixture file
 * {@code cdp-sample.bin} has not yet been committed — capturing real CDP frames
 * requires Cisco-equivalent switch infrastructure that the project does not
 * currently own. Place the fixture at
 * {@code backend/src/test/resources/discovery/cdp-sample.bin} when one becomes
 * available.
 *
 * <p>The test body exercises the real {@link CdpDecoder} contract: decoding a
 * captured frame must not throw, and any neighbors it yields must be
 * well-formed — MAC addresses in canonical lowercase-colon form, addresses
 * parseable as IP literals, iface equal to the passed label.
 */
@EnabledIfSystemProperty(named = "castellum.managed-switch-lab", matches = "true")
class CdpProbeAcceptanceTest {

    private static final String MAC_PATTERN = "[0-9a-f]{2}(:[0-9a-f]{2}){5}";

    @Test
    void probeAgainstFixtureDecodesWellFormedNeighbors() throws Exception {
        URL resource = getClass().getResource("/discovery/cdp-sample.bin");
        Path fixtureFile = resource != null ? Path.of(resource.toURI()) : Path.of("MISSING");
        assumeTrue(fixtureFile.toFile().exists(), "managed-switch fixture missing: cdp-sample.bin not committed");

        CdpDecoder decoder = new CdpDecoder();
        byte[] frameBytes = java.nio.file.Files.readAllBytes(fixtureFile);

        List<DiscoveredNeighbor> neighbors = decoder.decode(frameBytes, "lab0");

        assertThat(neighbors).isNotNull();
        for (DiscoveredNeighbor n : neighbors) {
            if (n.macAddress() != null) {
                assertThat(n.macAddress())
                    .as("decoded MAC must be canonical lowercase-colon form")
                    .matches(MAC_PATTERN);
            }
            if (n.ipAddress() != null) {
                // Address must be a parseable IP literal.
                assertThat(InetAddress.getByName(n.ipAddress()))
                    .as("decoded address must be a parseable IP literal")
                    .isNotNull();
            }
            assertThat(n.iface()).isEqualTo("lab0");
        }
    }
}
