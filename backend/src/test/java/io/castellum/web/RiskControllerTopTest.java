package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntry;
import io.castellum.risk.KevEntryRepository;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies {@link RiskController#topRisk(Integer)} ranking, clamp, and RBAC semantics.
 */
@WebMvcTest(controllers = RiskController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class,
    RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class,
    io.castellum.risk.DeviceRiskService.class})
@WithMockUser(roles = "VIEWER")
class RiskControllerTopTest {

    @Autowired MockMvc mvc;
    @MockBean CveRepository cveRepo;
    @MockBean DeviceRepository deviceRepo;
    @MockBean EpssScoreRepository epssRepo;
    @MockBean KevEntryRepository kevRepo;
    @MockBean NetworkServiceRepository networkServiceRepository;
    @MockBean CveMatcher cveMatcher;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean JwtService jwtService;
    @MockBean AuditService auditService;
    @MockBean UserRepository userRepository;

    @Test
    void topRisk_emptyFleet_returnsEmptyArray() throws Exception {
        when(deviceRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/risk/top"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void topRisk_defaultN_returnsAtMost10() throws Exception {
        // 15 devices, all with same criticality & no CVE matches → all score 0 → still capped at 10
        List<Device> devices = new ArrayList<>();
        for (long i = 1; i <= 15; i++) {
            devices.add(new Device(i, "192.168.1." + i, null, null, null, null, Criticality.MEDIUM));
        }
        when(deviceRepo.findAll()).thenReturn(devices);
        when(networkServiceRepository.findByDeviceId(any())).thenReturn(List.of());

        mvc.perform(get("/api/risk/top"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.length()").value(10));
    }

    @Test
    void topRisk_explicitN_returnsThatMany() throws Exception {
        List<Device> devices = new ArrayList<>();
        for (long i = 1; i <= 15; i++) {
            devices.add(new Device(i, "192.168.1." + i, null, null, null, null, Criticality.MEDIUM));
        }
        when(deviceRepo.findAll()).thenReturn(devices);
        when(networkServiceRepository.findByDeviceId(any())).thenReturn(List.of());

        mvc.perform(get("/api/risk/top").param("n", "3"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.length()").value(3));
    }

    @Test
    void topRisk_n_clampedTo100Max() throws Exception {
        List<Device> devices = new ArrayList<>();
        for (long i = 1; i <= 150; i++) {
            devices.add(new Device(i, "192.168.1." + i, null, null, null, null, Criticality.MEDIUM));
        }
        when(deviceRepo.findAll()).thenReturn(devices);
        when(networkServiceRepository.findByDeviceId(any())).thenReturn(List.of());

        mvc.perform(get("/api/risk/top").param("n", "5000"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.length()").value(100));
    }

    @Test
    void topRisk_n_clampedTo1Min() throws Exception {
        List<Device> devices = new ArrayList<>();
        for (long i = 1; i <= 5; i++) {
            devices.add(new Device(i, "192.168.1." + i, null, null, null, null, Criticality.MEDIUM));
        }
        when(deviceRepo.findAll()).thenReturn(devices);
        when(networkServiceRepository.findByDeviceId(any())).thenReturn(List.of());

        mvc.perform(get("/api/risk/top").param("n", "0"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    void topRisk_sortedByScoreDescending() throws Exception {
        // Device 1: HIGH criticality + a CVE → higher score
        // Device 2: LOW criticality + no CVE → lower score
        // Device 3: CRITICAL criticality + a max-CVSS CVE → highest score
        Device d1 = new Device(1L, "192.168.1.1", "host-1", null, null, null, Criticality.HIGH);
        Device d2 = new Device(2L, "192.168.1.2", "host-2", null, null, null, Criticality.LOW);
        Device d3 = new Device(3L, "192.168.1.3", "host-3", null, null, null, Criticality.CRITICAL);
        when(deviceRepo.findAll()).thenReturn(List.of(d1, d2, d3));

        NetworkService svc1 = svc(10L, 22, "tcp", "openssh", "8.2", 1L);
        NetworkService svc3 = svc(30L, 80, "tcp", "nginx", "1.18", 3L);
        when(networkServiceRepository.findByDeviceId(1L)).thenReturn(List.of(svc1));
        when(networkServiceRepository.findByDeviceId(2L)).thenReturn(List.of());
        when(networkServiceRepository.findByDeviceId(3L)).thenReturn(List.of(svc3));

        Cve cveHigh = makeCve("CVE-HIGH", 7.8);
        Cve cveMax = makeCve("CVE-MAX", 10.0);
        when(cveMatcher.findVulnerable(anyString())).thenAnswer(inv -> {
            String cpe = inv.getArgument(0);
            if (cpe.contains("openssh")) return List.of(cveHigh);
            if (cpe.contains("nginx")) return List.of(cveMax);
            return List.of();
        });
        when(epssRepo.findAllByCveIdIn(any())).thenReturn(List.of());
        when(kevRepo.findAllByCveIdIn(any())).thenReturn(List.of());

        mvc.perform(get("/api/risk/top"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.length()").value(3))
           .andExpect(jsonPath("$[0].deviceId").value(3))   // CRITICAL + max CVSS first
           .andExpect(jsonPath("$[0].hostname").value("host-3"))
           .andExpect(jsonPath("$[0].criticality").value("CRITICAL"))
           .andExpect(jsonPath("$[1].deviceId").value(1))   // HIGH + 7.8 CVSS second
           .andExpect(jsonPath("$[2].deviceId").value(2));  // LOW + no CVE last
    }

    @Test
    void topRisk_includesKevCount() throws Exception {
        Device d1 = new Device(1L, "192.168.1.1", "host-1", null, null, null, Criticality.HIGH);
        when(deviceRepo.findAll()).thenReturn(List.of(d1));

        NetworkService svc1 = svc(10L, 22, "tcp", "openssh", "8.2", 1L);
        when(networkServiceRepository.findByDeviceId(1L)).thenReturn(List.of(svc1));

        Cve cve1 = makeCve("CVE-2020-15778", 7.8);
        Cve cve2 = makeCve("CVE-2020-14145", 5.9);
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve1, cve2));
        when(epssRepo.findAllByCveIdIn(any())).thenReturn(List.of());
        // Both CVEs are KEV-flagged
        KevEntry k1 = new KevEntry();
        k1.setCveId("CVE-2020-15778");
        k1.setIngestedAt(Instant.now());
        KevEntry k2 = new KevEntry();
        k2.setCveId("CVE-2020-14145");
        k2.setIngestedAt(Instant.now());
        when(kevRepo.findAllByCveIdIn(any())).thenReturn(List.of(k1, k2));

        mvc.perform(get("/api/risk/top"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$[0].kevCount").value(2));
    }

    @Test
    void anon_returns401() throws Exception {
        mvc.perform(get("/api/risk/top").with(anonymous()))
           .andExpect(status().isUnauthorized());
    }

    private static Cve makeCve(String id, double cvss) {
        Cve cve = new Cve();
        cve.setCveId(id);
        cve.setCvssV31Score(BigDecimal.valueOf(cvss));
        cve.setRawJson("{}");
        return cve;
    }

    private static NetworkService svc(long id, int port, String protocol, String name, String version, long deviceId) {
        NetworkService s = new NetworkService();
        s.setId(id);
        s.setDeviceId(deviceId);
        s.setPort(port);
        s.setProtocol(protocol);
        s.setName(name);
        s.setVersion(version);
        return s;
    }
}
