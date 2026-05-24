package io.castellum.scan;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure unit tests for {@link NmapOutputParser}. No Spring context required.
 * Fixtures are defined inline. Lines not matching any recognised pattern are
 * silently skipped — verified by the malformed-line test.
 */
class NmapOutputParserTest {

    private final NmapOutputParser parser = new NmapOutputParser();

    // -----------------------------------------------------------------------
    // Ping-sweep: "Host is up" lines
    // -----------------------------------------------------------------------

    @Test
    void pingSweep_hostIsUp_returnsDiscoveredHost() {
        String stdout = """
                Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-01 00:00 UTC
                Nmap scan report for 192.168.1.10
                Host is up (0.0010s latency).
                Nmap scan report for myrouter (192.168.1.1)
                Host is up (0.0005s latency).
                Nmap done: 256 IP addresses (2 hosts up) scanned in 3.00 seconds
                """;

        NmapOutputParser.ParsedScan result = parser.parse(stdout, ScanType.PING_SWEEP);

        assertEquals(2, result.hosts().size(), "both hosts must be discovered");
        NmapOutputParser.DiscoveredHost first = result.hosts().get(0);
        assertEquals("192.168.1.10", first.ipAddress());
        assertNull(first.hostname(), "IP-only host must have null hostname");

        NmapOutputParser.DiscoveredHost second = result.hosts().get(1);
        assertEquals("192.168.1.1", second.ipAddress());
        assertEquals("myrouter", second.hostname());

        assertTrue(result.services().isEmpty(),
            "ping-sweep must produce no services");
    }

    // -----------------------------------------------------------------------
    // Service detect: PORT STATE SERVICE VERSION lines
    // -----------------------------------------------------------------------

    @Test
    void serviceDetect_portLines_returnsDiscoveredServices() {
        String stdout = """
                Nmap scan report for 10.0.0.5
                Host is up (0.0010s latency).
                PORT     STATE SERVICE  VERSION
                22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
                80/tcp   open  http     Apache httpd 2.4.52
                443/tcp  open  https
                Nmap done: 1 IP address (1 host up) scanned in 5.00 seconds
                """;

        NmapOutputParser.ParsedScan result = parser.parse(stdout, ScanType.SERVICE_DETECT);

        assertEquals(1, result.hosts().size(), "one host must be present");
        assertEquals(3, result.services().size(), "three services must be detected");

        NmapOutputParser.DiscoveredService ssh = result.services().get(0);
        assertEquals("10.0.0.5", ssh.ipAddress());
        assertEquals(22, ssh.port());
        assertEquals("tcp", ssh.protocol());
        assertEquals("ssh", ssh.name());
        assertTrue(ssh.version().contains("OpenSSH"),
            "SSH service version must contain 'OpenSSH'");

        NmapOutputParser.DiscoveredService https = result.services().get(2);
        assertEquals(443, https.port());
        assertEquals("https", https.name());
        // No version string present — should be empty string
        assertEquals("", https.version());
    }

    // -----------------------------------------------------------------------
    // Empty / no-host output
    // -----------------------------------------------------------------------

    @Test
    void emptyOutput_returnsEmptyResult() {
        NmapOutputParser.ParsedScan result = parser.parse("", ScanType.PING_SWEEP);
        assertTrue(result.hosts().isEmpty(), "empty stdout must produce no hosts");
        assertTrue(result.services().isEmpty(), "empty stdout must produce no services");
    }

    @Test
    void nullOutput_returnsEmptyResult() {
        NmapOutputParser.ParsedScan result = parser.parse(null, ScanType.PING_SWEEP);
        assertTrue(result.hosts().isEmpty(), "null stdout must produce no hosts");
        assertTrue(result.services().isEmpty(), "null stdout must produce no services");
    }

    // -----------------------------------------------------------------------
    // Malformed / unrecognised lines are skipped
    // -----------------------------------------------------------------------

    @Test
    void malformedLines_areSilentlySkipped() {
        String stdout = """
                THIS IS GARBAGE
                !!!NOT A VALID LINE!!!
                0/tcp garbage garbage garbage
                Nmap scan report for 10.1.1.1
                Host is up
                """;

        NmapOutputParser.ParsedScan result = parser.parse(stdout, ScanType.PING_SWEEP);

        // The garbage lines must not blow up, and the valid host must still be found.
        assertEquals(1, result.hosts().size(), "valid host must be found despite malformed lines");
        assertEquals("10.1.1.1", result.hosts().get(0).ipAddress());
    }
}
