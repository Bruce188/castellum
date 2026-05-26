package io.castellum.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditLogRepository;
import io.castellum.cve.Cve;
import io.castellum.cve.CveCpeMatch;
import io.castellum.cve.CveCpeMatchRepository;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import io.castellum.risk.EpssClient;
import io.castellum.risk.EpssScore;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevClient;
import io.castellum.risk.KevEntry;
import io.castellum.risk.KevEntryRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
// Use @WithMockUser for all test methods — the full Spring Security chain is active.
@WithMockUser(roles = "ADMIN")
class GraphControllerIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private DeviceRepository deviceRepo;
    @Autowired private NetworkServiceRepository serviceRepo;
    @Autowired private CveRepository cveRepo;
    @Autowired private CveCpeMatchRepository cveCpeMatchRepo;
    @Autowired private EpssScoreRepository epssRepo;
    @Autowired private KevEntryRepository kevRepo;
    @SuppressWarnings("unused")
    @Autowired private AuditLogRepository auditLogRepo;
    @Autowired private ObjectMapper objectMapper;

    // Stub external feed clients to keep the test hermetic.
    @MockBean private EpssClient epssClient;
    @MockBean private KevClient kevClient;

    @BeforeEach
    void cleanState() {
        cveCpeMatchRepo.deleteAll();
        cveRepo.deleteAll();
        epssRepo.deleteAll();
        kevRepo.deleteAll();
        serviceRepo.deleteAll();
        deviceRepo.deleteAll();
        // Note: AuditLogRepository is append-only — no deleteAll. Tests use snapshot counts instead.
    }

    @AfterEach
    void teardown() {
        cveCpeMatchRepo.deleteAll();
        cveRepo.deleteAll();
        epssRepo.deleteAll();
        kevRepo.deleteAll();
        serviceRepo.deleteAll();
        deviceRepo.deleteAll();
    }

    @Test
    void getShortestPath_withMissingFromOrTo_returns404() throws Exception {
        Device d = deviceRepo.save(new Device(null, "10.0.0.10", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.MEDIUM));
        mockMvc.perform(get("/api/graph/shortest-path")
                .param("from", String.valueOf(999_999L))
                .param("to", String.valueOf(d.getId())))
            .andExpect(status().isNotFound());
    }

    @Test
    void getShortestPath_withSameDevice_returns400() throws Exception {
        Device d = deviceRepo.save(new Device(null, "10.0.0.10", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.MEDIUM));
        mockMvc.perform(get("/api/graph/shortest-path")
                .param("from", String.valueOf(d.getId()))
                .param("to", String.valueOf(d.getId())))
            .andExpect(status().isBadRequest());
    }

    @Test
    void getShortestPath_withNonPositiveId_returns400() throws Exception {
        Device d = deviceRepo.save(new Device(null, "10.0.0.10", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.MEDIUM));
        mockMvc.perform(get("/api/graph/shortest-path")
                .param("from", "-1")
                .param("to", String.valueOf(d.getId())))
            .andExpect(status().isBadRequest());
    }

    @Test
    void getShortestPath_returnsExpectedHopShape() throws Exception {
        // Seed 3 devices in 10.0.0.0/24 + an OpenSSH 8.2 service on the last device + CVE-2020-15778.
        Device d1 = deviceRepo.save(new Device(null, "10.0.0.10", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.HIGH));
        Device d2 = deviceRepo.save(new Device(null, "10.0.0.42", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.HIGH));
        Device d3 = deviceRepo.save(new Device(null, "10.0.0.99", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.HIGH));

        serviceRepo.save(new NetworkService(null, d3.getId(), 22, "tcp", "openssh", "8.2", Instant.EPOCH));

        Cve cve = new Cve();
        cve.setCveId("CVE-2020-15778");
        cve.setCvssV31Score(new BigDecimal("7.8"));
        cve.setLastModified(Instant.now());
        cve.setRawJson("{}");
        cve = cveRepo.save(cve);

        CveCpeMatch match = new CveCpeMatch();
        match.setCveFk(cve.getId());
        match.setCpe23Uri("cpe:2.3:a:openssh:openssh:8.2:*:*:*:*:*:*:*");
        match.setVulnerable(true);
        cveCpeMatchRepo.save(match);

        EpssScore epss = new EpssScore();
        epss.setCveId("CVE-2020-15778");
        epss.setEpss(new BigDecimal("0.5"));
        epss.setPercentile(new BigDecimal("0.95"));
        epss.setScoreDate(LocalDate.now());
        epssRepo.save(epss);

        KevEntry kev = new KevEntry();
        kev.setCveId("CVE-2020-15778");
        kev.setVendorProject("OpenBSD");
        kev.setProduct("OpenSSH");
        kev.setVulnerabilityName("OpenSSH RCE");
        kev.setDateAdded(LocalDate.now());
        kev.setIngestedAt(Instant.now());
        kevRepo.save(kev);

        MvcResult result = mockMvc.perform(get("/api/graph/shortest-path")
                .param("from", String.valueOf(d1.getId()))
                .param("to", String.valueOf(d3.getId())))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.pathFound").value(true))
            .andExpect(jsonPath("$.hops").isArray())
            .andReturn();

        JsonNode root = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(root.get("totalHops").asInt()).isGreaterThanOrEqualTo(1);
        // First hop should have null edgeType.
        JsonNode firstHop = root.get("hops").get(0);
        assertThat(firstHop.get("edgeType").isNull()).isTrue();
        // Final hop's cumulativeRisk equals top-level.
        JsonNode lastHop = root.get("hops").get(root.get("hops").size() - 1);
        assertThat(lastHop.get("cumulativeRisk").decimalValue())
            .isEqualByComparingTo(root.get("cumulativeRisk").decimalValue());
    }

    @Test
    void getShortestPath_noPath_returnsPathFoundFalse() throws Exception {
        Device d1 = deviceRepo.save(new Device(null, "10.0.0.10", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.MEDIUM));
        Device d2 = deviceRepo.save(new Device(null, "10.0.1.20", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.MEDIUM));
        mockMvc.perform(get("/api/graph/shortest-path")
                .param("from", String.valueOf(d1.getId()))
                .param("to", String.valueOf(d2.getId())))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.pathFound").value(false))
            .andExpect(jsonPath("$.totalHops").value(0))
            .andExpect(jsonPath("$.hops").isEmpty());
    }
}
