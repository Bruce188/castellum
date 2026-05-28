package io.castellum.scan;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertThrows;

class NmapRunnerInjectionTest {

    private final NmapRunner runner = new NmapRunner();

    @ParameterizedTest
    @ValueSource(strings = {
        "; rm -rf /",
        "192.168.1.0/24; ls",
        "$(whoami)",
        "`id`",
        "",
        "foo"
    })
    void run_rejectsInjectionPayload(String payload) {
        assertThrows(IllegalArgumentException.class, () -> runner.run(payload, ScanType.PING_SWEEP),
            "Expected IllegalArgumentException for payload: " + payload);
    }

    @org.junit.jupiter.api.Test
    void run_rejectsNullCidr() {
        // Cast disambiguates the String-CIDR overload from the List-of-hosts overload.
        assertThrows(IllegalArgumentException.class, () -> runner.run((String) null, ScanType.PING_SWEEP),
            "Expected IllegalArgumentException for null CIDR");
    }
}
