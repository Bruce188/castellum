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

        assertEquals(4, result.services().size(),
            "four open services must be discovered (22, 1071, 3000, 5432)");
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
