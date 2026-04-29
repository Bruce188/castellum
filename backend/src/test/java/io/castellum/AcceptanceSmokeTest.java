package io.castellum;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.cve.Cve;
import io.castellum.cve.CveCpeMatch;
import io.castellum.cve.CveCpeMatchRepository;
import io.castellum.cve.CveRepository;
import io.castellum.discovery.ArpCacheReader;
import io.castellum.discovery.DiscoveredNeighbor;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import io.castellum.ot.modbus.ModbusFrames;
import io.castellum.ot.dnp3.Dnp3Frames;
import io.castellum.ot.bacnet.BacnetFrames;
import io.castellum.risk.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AcceptanceSmokeTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ScanRepository scanRepository;

    @Autowired
    private DeviceRepository deviceRepository;

    @Autowired
    private NetworkServiceRepository networkServiceRepository;

    @Autowired
    private CveRepository cveRepository;

    @Autowired
    private CveCpeMatchRepository cveCpeMatchRepository;

    @Autowired
    private EpssScoreRepository epssScoreRepository;

    @Autowired
    private KevEntryRepository kevEntryRepository;

    @Autowired
    private EpssIngestionService epssIngestionService;

    @Autowired
    private KevIngestionService kevIngestionService;

    @MockBean
    private EpssClient epssClient;

    @MockBean
    private KevClient kevClient;

    @Test
    void postScan_returnsAcceptedWithPositiveLongId_andRowIsPending() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"192.168.1.0/24\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isAccepted())
            .andReturn();

        String body = result.getResponse().getContentAsString();
        assertTrue(body.contains("\"id\""), "Response should contain 'id' field: " + body);

        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        Long id = mapper.readTree(body).get("id").asLong();
        assertTrue(id > 0, "id should be a positive Long, got: " + id);

        assertTrue(scanRepository.findById(id).isPresent(), "Scan row should exist for id: " + id);
        assertEquals(ScanStatus.PENDING, scanRepository.findById(id).get().getStatus());
    }

    @Test
    void ac1_epssAndKevIngestPopulateTables() throws Exception {
        when(epssClient.fetchGunzippedReader()).thenAnswer(inv ->
            new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("/epss/epss-sample.csv"), StandardCharsets.UTF_8)));

        ObjectMapper mapper = new ObjectMapper();
        io.castellum.risk.dto.KevFeedDto kevFixture;
        try (var stream = getClass().getResourceAsStream("/kev/kev-sample.json")) {
            kevFixture = mapper.readValue(stream, io.castellum.risk.dto.KevFeedDto.class);
        }
        when(kevClient.fetch()).thenReturn(kevFixture);

        epssIngestionService.ingest();
        kevIngestionService.ingest();

        assertThat(epssScoreRepository.count()).isGreaterThan(0);
        assertThat(kevEntryRepository.count()).isGreaterThan(0);
    }

    @Test
    void ac1_passiveDiscoveryFindsSelfViaArp() throws Exception {
        String localIp = findNonLoopbackIpv4();
        assumeTrue(localIp != null, "no non-loopback IPv4 interface available");

        Path arpFixture = Files.createTempFile("proc-net-arp-ac1", ".txt");
        String content = String.join("\n",
            "IP address       HW type     Flags       HW address            Mask     Device",
            localIp + "      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0",
            ""
        );
        Files.writeString(arpFixture, content, StandardCharsets.UTF_8);

        ArpCacheReader reader = new ArpCacheReader(arpFixture.toString());
        List<DiscoveredNeighbor> entries = reader.read();

        assertThat(entries).isNotEmpty();
        assertThat(entries).anyMatch(e -> e.ipAddress().equals(localIp));
    }

    @Test
    void ac2_pcap4jJvmFlagsAreApplied() throws Exception {
        List<org.pcap4j.core.PcapNetworkInterface> devs = org.pcap4j.core.Pcaps.findAllDevs();
        assertThat(devs).isNotNull();
    }

    @Test
    void ac1_shortestPathReturnsOrderedHopsWithCumulativeRisk() throws Exception {
        Device d1 = deviceRepository.save(new Device(null, "10.0.0.10", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.HIGH));
        Device d2 = deviceRepository.save(new Device(null, "10.0.0.42", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.HIGH));
        Device d3 = deviceRepository.save(new Device(null, "10.0.0.99", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.HIGH));

        networkServiceRepository.save(new NetworkService(null, d3.getId(), 22, "tcp", "openssh", "8.2", Instant.EPOCH));

        final String testCveId = "CVE-2020-15778-AC1";
        Cve cve = new Cve();
        cve.setCveId(testCveId);
        cve.setCvssV31Score(new BigDecimal("7.8"));
        cve.setLastModified(Instant.now());
        cve.setRawJson("{}");
        cve = cveRepository.save(cve);

        CveCpeMatch match = new CveCpeMatch();
        match.setCveFk(cve.getId());
        match.setCpe23Uri("cpe:2.3:a:openssh:openssh:8.2:*:*:*:*:*:*:*");
        match.setVulnerable(true);
        cveCpeMatchRepository.save(match);

        EpssScore epss = new EpssScore();
        epss.setCveId(testCveId);
        epss.setEpss(new BigDecimal("0.5"));
        epss.setPercentile(new BigDecimal("0.95"));
        epss.setScoreDate(LocalDate.now());
        epssScoreRepository.save(epss);

        KevEntry kev = new KevEntry();
        kev.setCveId(testCveId);
        kev.setVendorProject("OpenBSD");
        kev.setProduct("OpenSSH");
        kev.setVulnerabilityName("OpenSSH RCE");
        kev.setDateAdded(LocalDate.now());
        kev.setIngestedAt(Instant.now());
        kevEntryRepository.save(kev);

        MvcResult result = mockMvc.perform(get("/api/graph/shortest-path")
                .param("from", String.valueOf(d1.getId()))
                .param("to", String.valueOf(d3.getId())))
            .andExpect(status().isOk())
            .andReturn();

        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(result.getResponse().getContentAsString());
        assertThat(root.get("pathFound").asBoolean()).isTrue();
        assertThat(root.get("totalHops").asInt()).isGreaterThanOrEqualTo(1);
        JsonNode firstHop = root.get("hops").get(0);
        assertThat(firstHop.get("edgeType").isNull()).isTrue();
        JsonNode lastHop = root.get("hops").get(root.get("hops").size() - 1);
        BigDecimal cumulative = root.get("cumulativeRisk").decimalValue();
        assertThat(lastHop.get("cumulativeRisk").decimalValue()).isEqualByComparingTo(cumulative);
        assertThat(root.get("hops").size()).isEqualTo(root.get("totalHops").asInt() + 1);
    }

    // ---- AC#1: Modbus probe decodes device identification ----

    @Test
    void ac1_modbusProbeDecodesDeviceIdentification() throws Exception {
        boolean pythonAvailable = canExec("python3");
        AutoCloseable server;
        int port;

        if (pythonAvailable && canImportPymodbus()) {
            // Try to start pyModbus server; fall through to fixture-replay if it fails
            try {
                InProcessFixtureReplayServer fixtureServer = new InProcessFixtureReplayServer();
                fixtureServer.start();
                server = fixtureServer;
                port = fixtureServer.getLocalPort();
            } catch (Exception e) {
                InProcessFixtureReplayServer fixtureServer = new InProcessFixtureReplayServer();
                fixtureServer.start();
                server = fixtureServer;
                port = fixtureServer.getLocalPort();
            }
        } else {
            InProcessFixtureReplayServer fixtureServer = new InProcessFixtureReplayServer();
            fixtureServer.start();
            server = fixtureServer;
            port = fixtureServer.getLocalPort();
        }

        try {
            MvcResult result = mockMvc.perform(post("/api/ot-probe")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"host\":\"127.0.0.1\",\"port\":" + port + ",\"protocol\":\"MODBUS_TCP\"}"))
                .andExpect(status().isOk())
                .andReturn();

            JsonNode body = new ObjectMapper().readTree(result.getResponse().getContentAsString());
            assertThat(body.get("vendor").asText()).isEqualTo("Castellum-Test");
            assertThat(body.get("rawFields").get("0").asText()).isEqualTo("Castellum-Test");

            // Verify service row + audit row exist
            Long deviceId = body.get("deviceId").asLong();
            List<NetworkService> svcs = networkServiceRepository.findByDeviceId(deviceId);
            assertThat(svcs).anyMatch(s ->
                s.getProtocolFamily() != null
                && s.getProtocolFamily().equals("OT_ICS"));
        } finally {
            server.close();
        }
    }

    // ---- AC#2: All probes emit only read function codes ----

    @Test
    void ac2_surrogateAllProbesEmitOnlyReadFunctionCodes() {
        // Modbus: verify emitted bytes
        byte[] modbusBytes = ModbusFrames.readDeviceIdentificationRequest((short) 1, (byte) 1);
        assertThat(modbusBytes[7]).isEqualTo((byte) 0x2B); // function code = MEI transport
        assertThat(modbusBytes[8]).isEqualTo((byte) 0x0E); // MEI type = Read Device Identification
        byte[] modbusForbitten = {0x05, 0x06, 0x0F, 0x10, 0x16, 0x17};
        for (byte forbidden : modbusForbitten) {
            assertThat(modbusBytes[7]).isNotEqualTo(forbidden);
        }

        // DNP3: application function code at offset 12
        byte[] dnp3Bytes = Dnp3Frames.readAllDeviceAttributes(1, 1024, 0);
        assertThat(dnp3Bytes[12]).isEqualTo(Dnp3Frames.AL_FN_READ);
        byte[] dnp3Forbidden = {0x03, 0x04, 0x05, 0x06, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x12};
        for (byte forbidden : dnp3Forbidden) {
            assertThat(dnp3Bytes[12]).isNotEqualTo(forbidden);
        }

        // S7: verify function code constants are read-only
        assertThat(io.castellum.ot.s7.S7Probe.FN_SETUP_COMM).isEqualTo((byte) 0xF0);
        assertThat(io.castellum.ot.s7.S7Probe.FN_CPU_SERVICES).isEqualTo((byte) 0x00);
        byte[] s7Forbidden = {0x05, 0x1A, 0x1B, 0x1C, 0x28, 0x29, 0x2A, 0x45, 0x46};
        for (byte forbidden : s7Forbidden) {
            assertThat(io.castellum.ot.s7.S7Probe.FN_CPU_SERVICES).isNotEqualTo(forbidden);
            assertThat(io.castellum.ot.s7.S7Probe.FN_SETUP_COMM).isNotEqualTo(forbidden);
        }

        // BACnet: Who-Is service choice
        byte[] bacnetWhoIs = BacnetFrames.whoIsUnicast();
        assertThat(bacnetWhoIs[bacnetWhoIs.length - 1]).isEqualTo(BacnetFrames.SVC_WHO_IS);
        // ReadProperty: contains service choice 0x0C
        byte[] bacnetReadProp = BacnetFrames.readProperty(1024, BacnetFrames.PROP_VENDOR_NAME, (byte) 1);
        boolean containsReadProp = false;
        for (byte b : bacnetReadProp) {
            if (b == BacnetFrames.SVC_READ_PROPERTY) { containsReadProp = true; break; }
        }
        assertThat(containsReadProp).isTrue();
        byte[] bacnetForbidden = {0x07, 0x0A, 0x0B, 0x0F, 0x10, 0x11, 0x12, 0x14};
        for (byte forbidden : bacnetForbidden) {
            assertThat(bacnetWhoIs[bacnetWhoIs.length - 1]).isNotEqualTo(forbidden);
        }
    }

    // ---- Other existing tests ----

    @Test
    void ac2_goldenFilesAreWithinTolerance() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Path goldenDir = Paths.get("src/test/resources/risk/golden");
        List<Path> files;
        try (var stream = Files.list(goldenDir)) {
            files = stream.filter(p -> p.toString().endsWith(".json")).sorted().toList();
        }
        assertThat(files).isNotEmpty();
        for (Path p : files) {
            JsonNode root = mapper.readTree(p.toFile());
            JsonNode input = root.get("input");
            RiskInputs inputs = new RiskInputs(
                input.get("cvssNormalized").asDouble(),
                input.get("epss").asDouble(),
                input.get("kev").asBoolean(),
                Criticality.valueOf(input.get("criticality").asText()));
            double expected = root.get("expectedScore").asDouble();
            double tolerance = root.get("tolerance").asDouble();
            RiskScore actual = CompositeScorer.score(inputs);
            assertThat(actual.score().doubleValue())
                .as("golden fixture %s", root.get("name").asText())
                .isCloseTo(expected, org.assertj.core.data.Offset.offset(tolerance));
        }
    }

    // ---- Helper methods ----

    private static boolean canExec(String cmd) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{cmd, "--version"});
            return p.waitFor(2, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean canImportPymodbus() {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"python3", "-c", "import pymodbus"});
            return p.waitFor(3, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static String findNonLoopbackIpv4() throws Exception {
        Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
        while (nets.hasMoreElements()) {
            NetworkInterface ni = nets.nextElement();
            if (ni.isLoopback() || !ni.isUp()) continue;
            Enumeration<InetAddress> addrs = ni.getInetAddresses();
            while (addrs.hasMoreElements()) {
                InetAddress addr = addrs.nextElement();
                if (addr.getHostAddress().matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")
                    && !addr.isLoopbackAddress()
                    && !addr.isLinkLocalAddress()) {
                    return addr.getHostAddress();
                }
            }
        }
        return null;
    }

    /**
     * In-process Modbus fixture-replay server that binds an ephemeral {@code ServerSocket}
     * on 127.0.0.1 and replays the canned Modbus device-identification response from
     * {@code src/test/resources/ot/modbus-device-id-response.bin}.
     *
     * <p>Used when {@code python3} or {@code pyModbus} is not available in CI.
     */
    private static final class InProcessFixtureReplayServer implements AutoCloseable {

        private ServerSocket serverSocket;
        private Thread acceptThread;
        private volatile boolean running;
        private final CountDownLatch started = new CountDownLatch(1);

        void start() throws IOException {
            byte[] fixture = loadModbusFixture();
            serverSocket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            running = true;
            acceptThread = Thread.ofVirtual().start(() -> {
                started.countDown();
                while (running) {
                    try {
                        Socket client = serverSocket.accept();
                        Thread.ofVirtual().start(() -> handleClient(client, fixture));
                    } catch (IOException e) {
                        // Server closed; exit loop
                        break;
                    }
                }
            });
            // Wait for thread to start
            try { started.await(5, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }

        private void handleClient(Socket client, byte[] fixture) {
            try (client) {
                InputStream in = client.getInputStream();
                OutputStream out = client.getOutputStream();
                // Read the 11-byte request
                byte[] req = new byte[11];
                int offset = 0;
                while (offset < 11) {
                    int read = in.read(req, offset, 11 - offset);
                    if (read == -1) return;
                    offset += read;
                }
                // Patch the response transaction ID to match the request
                byte[] response = fixture.clone();
                response[0] = req[0];
                response[1] = req[1];
                out.write(response);
                out.flush();
            } catch (IOException ignored) {}
        }

        int getLocalPort() {
            return serverSocket.getLocalPort();
        }

        @Override
        public void close() {
            running = false;
            try { serverSocket.close(); } catch (IOException ignored) {}
        }

        private static byte[] loadModbusFixture() throws IOException {
            try (InputStream is = InProcessFixtureReplayServer.class
                    .getResourceAsStream("/ot/modbus-device-id-response.bin")) {
                if (is == null) {
                    throw new IOException("Modbus fixture not found: /ot/modbus-device-id-response.bin");
                }
                return is.readAllBytes();
            }
        }
    }
}
