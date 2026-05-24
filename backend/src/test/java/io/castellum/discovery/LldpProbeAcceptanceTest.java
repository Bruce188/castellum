package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.net.URL;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Acceptance test for the LLDP probe path against a captured fixture.
 *
 * <p>Gated by the {@code managed-switch-lab} Maven profile
 * ({@code mvn test -Pmanaged-switch-lab}), which sets
 * {@code castellum.managed-switch-lab=true}. Default {@code mvn test} skips
 * this class silently with no JUnit warning.
 *
 * <p>Even when the profile is active, the test aborts gracefully via
 * {@link org.junit.jupiter.api.Assumptions#assumeTrue} if the fixture file
 * {@code lldp-sample.bin} has not yet been committed — capturing real LLDP
 * frames requires managed-switch infrastructure that the project does not
 * currently own. Place the fixture at
 * {@code backend/src/test/resources/discovery/lldp-sample.bin} when one
 * becomes available.
 *
 * <p>The test body pins the {@link LldpDecoder} stub contract: calling
 * {@code decode()} must throw {@link UnsupportedOperationException} with a
 * message containing {@code "designed-but-untested"}. Replacing the stub with
 * real decoding logic is out of scope for this feature.
 */
@EnabledIfSystemProperty(named = "castellum.managed-switch-lab", matches = "true")
class LldpProbeAcceptanceTest {

    @Test
    void probeAgainstFixtureRespectsStubContract() throws Exception {
        URL resource = getClass().getResource("/discovery/lldp-sample.bin");
        Path fixtureFile = resource != null ? Path.of(resource.toURI()) : Path.of("MISSING");
        assumeTrue(fixtureFile.toFile().exists(), "managed-switch fixture missing: lldp-sample.bin not committed");

        LldpDecoder decoder = new LldpDecoder();
        byte[] frameBytes = java.nio.file.Files.readAllBytes(fixtureFile);

        assertThatThrownBy(() -> decoder.decode(frameBytes))
            .isInstanceOf(UnsupportedOperationException.class)
            .hasMessageContaining("designed-but-untested");
    }
}
