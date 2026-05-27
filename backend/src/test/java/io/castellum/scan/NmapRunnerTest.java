package io.castellum.scan;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure unit tests for NmapRunner.buildArgv — no nmap binary is spawned.
 */
class NmapRunnerTest {

    private static final String VALID_CIDR = "192.168.1.0/24";

    // NmapRunner constructed with no-arg ctor picks up NmapScanProperties defaults.
    private final NmapRunner runner = new NmapRunner();

    @Test
    void buildArgv_serviceDetect_containsPn() {
        List<String> argv = runner.buildArgv(VALID_CIDR, ScanType.SERVICE_DETECT);
        assertTrue(argv.contains("-Pn"),
            "SERVICE_DETECT argv must contain -Pn; got: " + argv);
    }

    @Test
    void buildArgv_pingSweep_omitsPn() {
        List<String> argv = runner.buildArgv(VALID_CIDR, ScanType.PING_SWEEP);
        assertFalse(argv.contains("-Pn"),
            "PING_SWEEP argv must NOT contain -Pn (AC5); got: " + argv);
    }

    @Test
    void buildArgv_osFingerprint_containsPn() {
        List<String> argv = runner.buildArgv(VALID_CIDR, ScanType.OS_FINGERPRINT);
        assertTrue(argv.contains("-Pn"),
            "OS_FINGERPRINT argv must contain -Pn; got: " + argv);
    }

    @Test
    void buildArgv_serviceDetect_usesLongHostTimeout() {
        List<String> argv = runner.buildArgv(VALID_CIDR, ScanType.SERVICE_DETECT);
        int hostTimeoutIdx = argv.indexOf("--host-timeout");
        assertTrue(hostTimeoutIdx >= 0, "argv must contain --host-timeout");
        assertEquals("180s", argv.get(hostTimeoutIdx + 1),
            "SERVICE_DETECT must use 180s host-timeout; got: " + argv.get(hostTimeoutIdx + 1));
    }

    @Test
    void buildArgv_pingSweep_usesShortHostTimeout() {
        List<String> argv = runner.buildArgv(VALID_CIDR, ScanType.PING_SWEEP);
        int hostTimeoutIdx = argv.indexOf("--host-timeout");
        assertTrue(hostTimeoutIdx >= 0, "argv must contain --host-timeout");
        String timeoutValue = argv.get(hostTimeoutIdx + 1);
        assertEquals("30s", timeoutValue,
            "PING_SWEEP must use 30s host-timeout (AC5); got: " + timeoutValue);
        assertNotEquals("180s", timeoutValue,
            "PING_SWEEP must NOT use 180s (long) host-timeout (AC5)");
    }

    @Test
    void buildArgv_startsWithNmapAndContainsCidr() {
        List<String> argv = runner.buildArgv(VALID_CIDR, ScanType.SERVICE_DETECT);
        assertEquals("nmap", argv.get(0), "first token must be 'nmap'");
        assertEquals(VALID_CIDR, argv.get(argv.size() - 1), "last token must be the cidr");
        assertTrue(argv.contains("-T4"), "argv must contain -T4");
        assertTrue(argv.contains("-sV"), "argv must contain -sV for SERVICE_DETECT");
    }

    @Test
    void buildArgv_emitsXmlToStdout() {
        // "-oX -" makes nmap write XML to stdout; the parser depends on XML for product/CPE.
        for (ScanType type : ScanType.values()) {
            List<String> argv = runner.buildArgv(VALID_CIDR, type);
            int oxIdx = argv.indexOf("-oX");
            assertTrue(oxIdx >= 0, type + " argv must contain -oX; got: " + argv);
            assertEquals("-", argv.get(oxIdx + 1),
                type + " -oX target must be '-' (stdout); got: " + argv);
        }
    }

    @Test
    void buildArgv_injectsConfiguredTimeout() {
        // Construct NmapRunner with custom NmapScanProperties (AC2 config wiring proof).
        NmapScanProperties customProps = new NmapScanProperties();
        customProps.setPortScanHostTimeout("99s");
        NmapRunner customRunner = new NmapRunner(customProps);

        List<String> argv = customRunner.buildArgv(VALID_CIDR, ScanType.SERVICE_DETECT);
        int hostTimeoutIdx = argv.indexOf("--host-timeout");
        assertTrue(hostTimeoutIdx >= 0, "argv must contain --host-timeout");
        assertEquals("99s", argv.get(hostTimeoutIdx + 1),
            "configured portScanHostTimeout sentinel '99s' must appear in argv; got: " + argv);
    }
}
