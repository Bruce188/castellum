package io.castellum.scan;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure unit tests for {@link NmapOutputParser}. No Spring context required.
 *
 * <p>Fixtures are real nmap {@code -oX -} XML captured under {@code src/test/resources/nmap/}.
 * Malformed input is handled defensively — verified by the malformed/empty/null tests.
 */
class NmapOutputParserTest {

    private final NmapOutputParser parser = new NmapOutputParser();

    private static String fixture(String name) throws IOException {
        try (InputStream in = NmapOutputParserTest.class.getResourceAsStream("/nmap/" + name)) {
            assertNotNull(in, "fixture /nmap/" + name + " must be on the test classpath");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static NmapOutputParser.DiscoveredService byPort(
            List<NmapOutputParser.DiscoveredService> services, int port) {
        Optional<NmapOutputParser.DiscoveredService> found =
            services.stream().filter(s -> s.port() == port).findFirst();
        assertTrue(found.isPresent(), "expected a service on port " + port);
        return found.get();
    }

    // -----------------------------------------------------------------------
    // Service detect: products + CPEs from the <service><cpe> elements
    // -----------------------------------------------------------------------

    @Test
    void serviceDetect_extractsHostHostnameAndOpenServices() throws IOException {
        NmapOutputParser.ParsedScan result =
            parser.parse(fixture("service-detect.xml"), ScanType.SERVICE_DETECT);

        assertEquals(1, result.hosts().size(), "one host must be discovered");
        NmapOutputParser.DiscoveredHost host = result.hosts().get(0);
        assertEquals("192.168.68.51", host.ipAddress());
        assertEquals("host.docker.internal", host.hostname());

        assertEquals(5, result.services().size(),
            "five open services must be discovered (22, 1071, 3000, 5432, 3306)");
    }

    @Test
    void serviceDetect_opensshProductAndCpe() throws IOException {
        NmapOutputParser.ParsedScan result =
            parser.parse(fixture("service-detect.xml"), ScanType.SERVICE_DETECT);

        NmapOutputParser.DiscoveredService ssh = byPort(result.services(), 22);
        assertEquals("192.168.68.51", ssh.ipAddress());
        assertEquals("tcp", ssh.protocol());
        assertEquals("ssh", ssh.name());
        assertEquals("OpenSSH", ssh.product());
        assertEquals("9.6p1 Ubuntu 3ubuntu13.16", ssh.version());
        // First application CPE wins; the o:linux:linux_kernel CPE is ignored.
        assertEquals("cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*", ssh.cpe23());
    }

    @Test
    void serviceDetect_nginxProductAndCpe() throws IOException {
        NmapOutputParser.ParsedScan result =
            parser.parse(fixture("service-detect.xml"), ScanType.SERVICE_DETECT);

        NmapOutputParser.DiscoveredService nginx = byPort(result.services(), 1071);
        assertEquals("http", nginx.name());
        assertEquals("nginx", nginx.product());
        assertEquals("1.29.8", nginx.version());
        assertEquals("cpe:2.3:a:igor_sysoev:nginx:1.29.8:*:*:*:*:*:*:*", nginx.cpe23());
    }

    @Test
    void serviceDetect_nodeJsCpeWithoutVersionPadsWildcard() throws IOException {
        NmapOutputParser.ParsedScan result =
            parser.parse(fixture("service-detect.xml"), ScanType.SERVICE_DETECT);

        NmapOutputParser.DiscoveredService node = byPort(result.services(), 3000);
        assertEquals("http", node.name());
        assertEquals("Node.js Express framework", node.product());
        // No version attribute on the service element → empty string.
        assertEquals("", node.version());
        // CPE has no version component → padded with '*'.
        assertEquals("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", node.cpe23());
    }

    @Test
    void serviceDetect_postgresCpeWithoutVersionPadsWildcard() throws IOException {
        NmapOutputParser.ParsedScan result =
            parser.parse(fixture("service-detect.xml"), ScanType.SERVICE_DETECT);

        NmapOutputParser.DiscoveredService pg = byPort(result.services(), 5432);
        assertEquals("postgresql", pg.name());
        assertEquals("PostgreSQL DB", pg.product());
        assertEquals("9.6.0 or later", pg.version());
        assertEquals("cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*", pg.cpe23());
    }

    @Test
    void serviceDetect_mysqlProductAndVersionNoCpe() throws IOException {
        NmapOutputParser.ParsedScan result =
            parser.parse(fixture("service-detect.xml"), ScanType.SERVICE_DETECT);

        NmapOutputParser.DiscoveredService mysql = byPort(result.services(), 3306);
        assertEquals("mysql", mysql.name());
        assertEquals("MySQL", mysql.product());
        assertEquals("8.0.46-1.el9", mysql.version());
        // nmap did not emit a <cpe> element — cpe23 must be null
        assertNull(mysql.cpe23());
    }

    // -----------------------------------------------------------------------
    // Ping-sweep: hosts up with no <ports>
    // -----------------------------------------------------------------------

    @Test
    void pingSweep_returnsUpHostsOnlyAndNoServices() throws IOException {
        NmapOutputParser.ParsedScan result =
            parser.parse(fixture("ping-sweep.xml"), ScanType.PING_SWEEP);

        // Two hosts up; the third (state="down") must be excluded.
        assertEquals(2, result.hosts().size(), "only up hosts must be returned");
        assertTrue(result.services().isEmpty(), "ping-sweep must produce no services");

        NmapOutputParser.DiscoveredHost first = result.hosts().get(0);
        assertEquals("192.168.1.10", first.ipAddress());
        assertNull(first.hostname(), "host without a <hostname> must have null hostname");

        NmapOutputParser.DiscoveredHost second = result.hosts().get(1);
        assertEquals("192.168.1.1", second.ipAddress());
        assertEquals("myrouter", second.hostname());
    }

    // -----------------------------------------------------------------------
    // Empty / null / malformed input is handled defensively
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

    @Test
    void malformedXml_returnsEmptyResultWithoutThrowing() {
        String garbage = "not <xml at all & definitely > broken";
        NmapOutputParser.ParsedScan result = parser.parse(garbage, ScanType.SERVICE_DETECT);
        assertTrue(result.hosts().isEmpty(), "malformed XML must produce no hosts");
        assertTrue(result.services().isEmpty(), "malformed XML must produce no services");
    }

    // -----------------------------------------------------------------------
    // OS fingerprint: <os><osmatch> elements from nmap -O
    // -----------------------------------------------------------------------

    @Test
    void osFingerprint_extractsHighestAccuracyOsMatch() throws IOException {
        NmapOutputParser.ParsedScan result =
            parser.parse(fixture("os-fingerprint.xml"), ScanType.SERVICE_DETECT);

        assertEquals(1, result.hosts().size(), "one host must be discovered");
        NmapOutputParser.DiscoveredHost host = result.hosts().get(0);
        assertEquals("192.168.68.51", host.ipAddress());

        assertNotNull(host.os(), "os() must not be null when <os><osmatch> is present");
        assertEquals("Linux 5.4 - 5.15", host.os().name(),
            "highest-accuracy osmatch name must be selected");
        assertEquals(96, host.os().accuracy(),
            "highest-accuracy osmatch accuracy must be 96");
        assertTrue(host.os().cpe().startsWith("cpe:/o:"),
            "cpe must start with cpe:/o: but was: " + host.os().cpe());
    }

    @Test
    void osFingerprint_multipleOsmatch_firstWins() throws IOException {
        NmapOutputParser.ParsedScan result =
            parser.parse(fixture("os-fingerprint.xml"), ScanType.SERVICE_DETECT);

        NmapOutputParser.DiscoveredHost host = result.hosts().get(0);
        assertNotNull(host.os(), "os() must not be null");
        assertNotEquals("Linux 4.15 - 5.8", host.os().name(),
            "the second (lower-accuracy) osmatch must not be selected");
    }

    @Test
    void noOsElement_yieldsNullOsMatch() throws IOException {
        NmapOutputParser.ParsedScan result =
            parser.parse(fixture("service-detect.xml"), ScanType.SERVICE_DETECT);

        assertEquals(1, result.hosts().size(), "one host expected in service-detect.xml");
        NmapOutputParser.DiscoveredHost host = result.hosts().get(0);
        assertNull(host.os(), "os() must be null when no <os> element is present");
    }

    @Test
    void osmatch_nonNumericAccuracy_yieldsNullAccuracy() {
        String xml = """
                <?xml version="1.0"?>
                <nmaprun>
                <host><status state="up" reason="echo-reply"/>
                <address addr="10.0.0.7" addrtype="ipv4"/>
                <hostnames></hostnames>
                <ports>
                <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
                </ports>
                <os><osmatch name="WeirdOS" accuracy="abc"/></os>
                </host>
                <runstats><finished/></runstats>
                </nmaprun>
                """;
        NmapOutputParser.ParsedScan result = parser.parse(xml, ScanType.SERVICE_DETECT);
        assertEquals(1, result.hosts().size(), "one host must be parsed");
        NmapOutputParser.DiscoveredHost host = result.hosts().get(0);
        assertNotNull(host.os(), "os() must not be null when <osmatch> is present");
        assertEquals("WeirdOS", host.os().name(), "name must be preserved even with bad accuracy");
        assertNull(host.os().accuracy(), "non-numeric accuracy must yield null");
    }

    // -----------------------------------------------------------------------
    // Host address keying: IPv4 preferred, IPv6-only fallback, no-IP skip
    // -----------------------------------------------------------------------

    @Test
    void ipv6OnlyHost_isKeyedByIpv6Address() {
        String xml = """
                <?xml version="1.0"?>
                <nmaprun>
                <host><status state="up" reason="nd-response"/>
                <address addr="fd12:3456::10" addrtype="ipv6"/>
                <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
                <hostnames></hostnames>
                <ports>
                <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
                </ports>
                </host>
                <runstats><finished/></runstats>
                </nmaprun>
                """;
        NmapOutputParser.ParsedScan result = parser.parse(xml, ScanType.SERVICE_DETECT);
        assertEquals(1, result.hosts().size(), "IPv6-only host must not be skipped");
        assertEquals("fd12:3456::10", result.hosts().get(0).ipAddress());
        assertEquals(1, result.services().size(), "the open port must yield a service");
        assertEquals("fd12:3456::10", result.services().get(0).ipAddress());
    }

    @Test
    void dualStackHost_prefersIpv4Address() {
        String xml = """
                <?xml version="1.0"?>
                <nmaprun>
                <host><status state="up" reason="echo-reply"/>
                <address addr="fe80::1" addrtype="ipv6"/>
                <address addr="192.168.1.20" addrtype="ipv4"/>
                <hostnames></hostnames>
                </host>
                <runstats><finished/></runstats>
                </nmaprun>
                """;
        NmapOutputParser.ParsedScan result = parser.parse(xml, ScanType.PING_SWEEP);
        assertEquals(1, result.hosts().size(), "dual-stack host must be discovered");
        assertEquals("192.168.1.20", result.hosts().get(0).ipAddress(),
            "IPv4 must win over IPv6 when both are present");
    }

    @Test
    void hostWithNoIpAddress_isSkipped() {
        // MAC-only host (no ipv4/ipv6 <address>) cannot key a device — skipped.
        String xml = """
                <?xml version="1.0"?>
                <nmaprun>
                <host><status state="up" reason="arp-response"/>
                <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
                <hostnames></hostnames>
                </host>
                <runstats><finished/></runstats>
                </nmaprun>
                """;
        NmapOutputParser.ParsedScan result = parser.parse(xml, ScanType.PING_SWEEP);
        assertTrue(result.hosts().isEmpty(), "host without any IP address must be skipped");
        assertTrue(result.services().isEmpty(), "skipped host must contribute no services");
    }

    @Test
    void closedPorts_areExcluded() {
        // A host with one open and one closed port; only the open one becomes a service.
        String xml = """
                <?xml version="1.0"?>
                <nmaprun>
                <host><status state="up" reason="user-set"/>
                <address addr="10.0.0.9" addrtype="ipv4"/>
                <hostnames></hostnames>
                <ports>
                <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
                <port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
                </ports>
                </host>
                <runstats><finished/></runstats>
                </nmaprun>
                """;
        NmapOutputParser.ParsedScan result = parser.parse(xml, ScanType.SERVICE_DETECT);
        assertEquals(1, result.services().size(), "only the open port must yield a service");
        assertEquals(22, result.services().get(0).port());
    }
}
