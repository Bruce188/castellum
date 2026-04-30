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
import io.castellum.risk.*;
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
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = RiskController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class RiskControllerDeviceRiskTest {

    @Autowired MockMvc mvc;
    @MockBean CveRepository cveRepo;
    @MockBean DeviceRepository deviceRepo;
    @MockBean EpssScoreRepository epssRepo;
    @MockBean KevEntryRepository kevRepo;
    @MockBean NetworkServiceRepository networkServiceRepository;
    @MockBean CveMatcher cveMatcher;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean
    JwtService jwtService;
    @MockBean AuditService auditService;
    @MockBean UserRepository userRepository;

    @Test
    void deviceRisk_unknownDevice_returns404() throws Exception {
        when(deviceRepo.findById(999L)).thenReturn(Optional.empty());
        mvc.perform(get("/api/risk/device/999"))
           .andExpect(status().isNotFound());
    }

    @Test
    void deviceRisk_noServices_returnsZero() throws Exception {
        Device d = new Device(1L, "192.168.1.10", null, null, null, null, Criticality.MEDIUM);
        when(deviceRepo.findById(1L)).thenReturn(Optional.of(d));
        when(networkServiceRepository.findByDeviceId(1L)).thenReturn(List.of());

        mvc.perform(get("/api/risk/device/1"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.deviceId").value(1))
           .andExpect(jsonPath("$.score").isNumber())
           .andExpect(jsonPath("$.topCveIds.length()").value(0));
    }

    @Test
    void deviceRisk_matchedCves_returnsMaxAndTopThree() throws Exception {
        Device d = new Device(1L, "192.168.1.10", null, null, null, null, Criticality.HIGH);
        when(deviceRepo.findById(1L)).thenReturn(Optional.of(d));
        NetworkService svc1 = new NetworkService();
        svc1.setId(10L);
        svc1.setDeviceId(1L);
        svc1.setPort(22);
        svc1.setProtocol("tcp");
        svc1.setName("openssh");
        svc1.setVersion("8.2");
        when(networkServiceRepository.findByDeviceId(1L)).thenReturn(List.of(svc1));

        Cve c1 = makeCve("CVE-2020-15778", 7.8);
        Cve c2 = makeCve("CVE-2020-14145", 5.9);
        Cve c3 = makeCve("CVE-2018-15473", 5.3);
        Cve c4 = makeCve("CVE-2017-15906", 5.0);
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(c1, c2, c3, c4));
        when(epssRepo.findByCveId(anyString())).thenReturn(Optional.empty());
        when(kevRepo.existsByCveId(anyString())).thenReturn(false);

        mvc.perform(get("/api/risk/device/1"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.score").isNotEmpty())
           .andExpect(jsonPath("$.topCveIds.length()").value(3))
           .andExpect(jsonPath("$.topCveIds[0]").value("CVE-2020-15778"));
    }

    @Test
    void anon_returns401() throws Exception {
        mvc.perform(get("/api/risk/device/1").with(anonymous()))
           .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_canRead_returns200() throws Exception {
        Device d = new Device(1L, "192.168.1.10", null, null, null, null, Criticality.MEDIUM);
        when(deviceRepo.findById(1L)).thenReturn(Optional.of(d));
        when(networkServiceRepository.findByDeviceId(1L)).thenReturn(List.of());

        mvc.perform(get("/api/risk/device/1"))
           .andExpect(status().isOk());
    }

    private static Cve makeCve(String id, double cvss) {
        Cve cve = new Cve();
        cve.setCveId(id);
        cve.setCvssV31Score(BigDecimal.valueOf(cvss));
        cve.setRawJson("{}");
        return cve;
    }
}
