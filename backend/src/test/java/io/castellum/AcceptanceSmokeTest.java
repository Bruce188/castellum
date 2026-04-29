package io.castellum;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.discovery.ArpCacheReader;
import io.castellum.discovery.DiscoveredNeighbor;
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
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.when;
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
