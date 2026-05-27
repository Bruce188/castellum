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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that {@link RiskController#deviceRisk} issues exactly one batch lookup per
 * EPSS/KEV repository regardless of matched-CVE count, and never falls back to the
 * per-CVE {@code findByCveId} / {@code existsByCveId} call sites.
 */
@WebMvcTest(controllers = RiskController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class,
    RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class,
    io.castellum.risk.DeviceRiskService.class})
@WithMockUser(roles = "VIEWER")
class RiskControllerDeviceRiskBatchTest {

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
    void deviceRisk_with15MatchedCves_callsFindAllByCveIdInOncePerRepo() throws Exception {
        seed15Cves();
        when(epssRepo.findAllByCveIdIn(any())).thenReturn(List.of());
        when(kevRepo.findAllByCveIdIn(any())).thenReturn(List.of());

        mvc.perform(get("/api/risk/device/1"))
           .andExpect(status().isOk());

        verify(epssRepo, times(1)).findAllByCveIdIn(any(Collection.class));
        verify(kevRepo, times(1)).findAllByCveIdIn(any(Collection.class));
    }

    @Test
    void deviceRisk_with15MatchedCves_neverCallsPerCveLookups() throws Exception {
        seed15Cves();
        when(epssRepo.findAllByCveIdIn(any())).thenReturn(List.of());
        when(kevRepo.findAllByCveIdIn(any())).thenReturn(List.of());

        mvc.perform(get("/api/risk/device/1"))
           .andExpect(status().isOk());

        verify(epssRepo, never()).findByCveId(anyString());
        verify(kevRepo, never()).existsByCveId(anyString());
    }

    @Test
    void deviceRisk_payloadShape_unchangedFromPriorBatch() throws Exception {
        // Two services × 4 distinct CVEs (HIGH-criticality device) — assert top-3 ordering
        // by descending composite score and the topmost CVE is returned in topCveIds[0].
        Device d = new Device(1L, "192.168.1.10", null, null, null, null, Criticality.HIGH);
        when(deviceRepo.findById(1L)).thenReturn(Optional.of(d));
        NetworkService svc1 = svc(10L, 22, "tcp", "openssh", "8.2");
        when(networkServiceRepository.findByDeviceId(1L)).thenReturn(List.of(svc1));

        Cve hi = makeCve("CVE-2020-15778", 9.8);
        Cve mid = makeCve("CVE-2020-14145", 5.9);
        Cve lo = makeCve("CVE-2018-15473", 5.3);
        Cve floor = makeCve("CVE-2017-15906", 5.0);
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(hi, mid, lo, floor));
        when(epssRepo.findAllByCveIdIn(any())).thenReturn(List.of());
        when(kevRepo.findAllByCveIdIn(any())).thenReturn(List.of());

        mvc.perform(get("/api/risk/device/1"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.score").isNotEmpty())
           .andExpect(jsonPath("$.topCveIds.length()").value(3))
           .andExpect(jsonPath("$.topCveIds[0]").value("CVE-2020-15778"));
    }

    private void seed15Cves() {
        Device d = new Device(1L, "192.168.1.10", null, null, null, null, Criticality.MEDIUM);
        when(deviceRepo.findById(1L)).thenReturn(Optional.of(d));
        NetworkService s1 = svc(10L, 22, "tcp", "openssh", "8.2");
        NetworkService s2 = svc(11L, 80, "tcp", "nginx", "1.20");
        NetworkService s3 = svc(12L, 443, "tcp", "openssl", "1.1.1");
        when(networkServiceRepository.findByDeviceId(1L)).thenReturn(List.of(s1, s2, s3));

        // 5 CVEs per service × 3 services = 15 unique CVEs.
        List<Cve> ssh = make5Cves("ssh");
        List<Cve> ngx = make5Cves("ngx");
        List<Cve> ssl = make5Cves("ssl");
        when(cveMatcher.findVulnerable(anyString())).thenAnswer(inv -> {
            String cpe = inv.getArgument(0);
            if (cpe.contains("openssh")) return ssh;
            if (cpe.contains("nginx")) return ngx;
            return ssl;
        });
    }

    private static List<Cve> make5Cves(String tag) {
        List<Cve> out = new ArrayList<>(5);
        for (int i = 0; i < 5; i++) {
            out.add(makeCve("CVE-" + tag + "-" + i, 5.0 + i));
        }
        return out;
    }

    private static Cve makeCve(String id, double cvss) {
        Cve cve = new Cve();
        cve.setCveId(id);
        cve.setCvssV31Score(BigDecimal.valueOf(cvss));
        cve.setRawJson("{}");
        return cve;
    }

    private static NetworkService svc(long id, int port, String protocol, String name, String version) {
        NetworkService s = new NetworkService();
        s.setId(id);
        s.setDeviceId(1L);
        s.setPort(port);
        s.setProtocol(protocol);
        s.setName(name);
        s.setVersion(version);
        return s;
    }
}
