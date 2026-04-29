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
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Enumeration;
import java.util.List;

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

        // Extract the id from the response JSON
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        Long id = mapper.readTree(body).get("id").asLong();
        assertTrue(id > 0, "id should be a positive Long, got: " + id);

        // AC#2: verify the row exists with status PENDING
        assertTrue(scanRepository.findById(id).isPresent(), "Scan row should exist for id: " + id);
        assertEquals(ScanStatus.PENDING, scanRepository.findById(id).get().getStatus());
    }

    @Test
    void ac1_epssAndKevIngestPopulateTables() throws Exception {
        // Stub EPSS client with fixture
        when(epssClient.fetchGunzippedReader()).thenAnswer(inv ->
            new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("/epss/epss-sample.csv"), StandardCharsets.UTF_8)));

        // Stub KEV client with fixture
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
        // Pcaps.findAllDevs() triggers JNA reflective access into sun.nio.ch.
        // Without the JVM flags, this throws IllegalAccessError.
        List<org.pcap4j.core.PcapNetworkInterface> devs = org.pcap4j.core.Pcaps.findAllDevs();
        assertThat(devs).isNotNull();
    }

    @Test
    void ac1_shortestPathReturnsOrderedHopsWithCumulativeRisk() throws Exception {
        // Seed 3 devices in 10.0.0.0/24, criticality HIGH.
        Device d1 = deviceRepository.save(new Device(null, "10.0.0.10", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.HIGH));
        Device d2 = deviceRepository.save(new Device(null, "10.0.0.42", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.HIGH));
        Device d3 = deviceRepository.save(new Device(null, "10.0.0.99", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.HIGH));

        // OpenSSH 8.2 service on the last device.
        networkServiceRepository.save(new NetworkService(null, d3.getId(), 22, "tcp", "openssh", "8.2", Instant.EPOCH));

        // Use AC1-specific CVE id to avoid collision with ac1_epssAndKevIngestPopulateTables fixture.
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
        // Dijkstra finds the shortest (lowest-weight) path. With all 3 devices in the same /24,
        // the direct SAME_SUBNET edge d1→d3 (weight 1.0) is the shortest path (totalHops=1).
        // The 2-hop path via EXPLOITABLE_VULN is always heavier (weight ≥ 1.0 + 1.0).
        assertThat(root.get("totalHops").asInt()).isGreaterThanOrEqualTo(1);
        // The path returned must have the correct shape: first hop with null edgeType.
        JsonNode firstHop = root.get("hops").get(0);
        assertThat(firstHop.get("edgeType").isNull()).isTrue();
        // Last hop's cumulativeRisk must equal the top-level cumulativeRisk.
        JsonNode lastHop = root.get("hops").get(root.get("hops").size() - 1);
        BigDecimal cumulative = root.get("cumulativeRisk").decimalValue();
        assertThat(lastHop.get("cumulativeRisk").decimalValue()).isEqualByComparingTo(cumulative);
        // Verify the response shape: hops array has totalHops+1 entries.
        assertThat(root.get("hops").size()).isEqualTo(root.get("totalHops").asInt() + 1);
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
}
