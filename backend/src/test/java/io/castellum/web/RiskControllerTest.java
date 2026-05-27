package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.config.SecurityConfig;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
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
import java.time.Instant;
import java.time.LocalDate;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(RiskController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class,
    io.castellum.risk.DeviceRiskService.class})
@WithMockUser(roles = "ADMIN")
class RiskControllerTest {

    @Autowired MockMvc mvc;
    @MockBean
    AuditService auditService;
    @MockBean CveRepository cveRepo;
    @MockBean DeviceRepository deviceRepo;
    @MockBean EpssScoreRepository epssRepo;
    @MockBean KevEntryRepository kevRepo;
    @MockBean NetworkServiceRepository networkServiceRepository;
    @MockBean CveMatcher cveMatcher;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean
    JwtService jwtService;
    @MockBean UserRepository userRepository;

    @Test
    void score_assemblesInputsAndReturnsScore() throws Exception {
        Cve cve = new Cve();
        cve.setCveId("CVE-2020-15778");
        cve.setCvssV31Score(BigDecimal.valueOf(7.8));
        when(cveRepo.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(cve));

        Device device = new Device();
        device.setIpAddress("10.0.0.1");
        device.setCriticality(Criticality.HIGH);
        when(deviceRepo.findById(42L)).thenReturn(Optional.of(device));

        EpssScore epss = new EpssScore(null, "CVE-2020-15778", BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.9), LocalDate.now(), Instant.now());
        when(epssRepo.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(epss));
        when(kevRepo.existsByCveId("CVE-2020-15778")).thenReturn(true);

        mvc.perform(get("/api/risk/score").param("cve", "CVE-2020-15778").param("device", "42"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.score").exists())
            .andExpect(jsonPath("$.cvssComponent").exists())
            .andExpect(jsonPath("$.kevComponent").exists());
    }

    @Test
    void score_returns404WhenCveNotFound() throws Exception {
        when(cveRepo.findByCveId(anyString())).thenReturn(Optional.empty());
        mvc.perform(get("/api/risk/score").param("cve", "CVE-9999-9999").param("device", "1"))
            .andExpect(status().isNotFound());
    }

    @Test
    void score_returns404WhenDeviceNotFound() throws Exception {
        Cve cve = new Cve();
        cve.setCveId("CVE-2020-15778");
        when(cveRepo.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(cve));
        when(deviceRepo.findById(anyLong())).thenReturn(Optional.empty());
        mvc.perform(get("/api/risk/score").param("cve", "CVE-2020-15778").param("device", "999"))
            .andExpect(status().isNotFound());
    }

    @Test
    void feedsStatus_returnsFreshness() throws Exception {
        when(epssRepo.count()).thenReturn(100L);
        when(epssRepo.findMaxScoreDate()).thenReturn(Optional.of(LocalDate.now()));
        when(kevRepo.count()).thenReturn(50L);
        when(kevRepo.findMaxIngestedAt()).thenReturn(Optional.of(Instant.now()));
        mvc.perform(get("/api/risk/feeds/status"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.epss.rowCount").value(100))
            .andExpect(jsonPath("$.kev.entryCount").value(50));
    }

    @Test
    void anon_returns401() throws Exception {
        mvc.perform(get("/api/risk/score")
                .with(anonymous())
                .param("cve", "CVE-2020-15778")
                .param("device", "42"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_canRead_returns200() throws Exception {
        Cve cve = new Cve();
        cve.setCveId("CVE-2020-15778");
        cve.setCvssV31Score(BigDecimal.valueOf(7.8));
        when(cveRepo.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(cve));

        Device device = new Device();
        device.setIpAddress("10.0.0.1");
        device.setCriticality(Criticality.HIGH);
        when(deviceRepo.findById(42L)).thenReturn(Optional.of(device));

        EpssScore epss = new EpssScore(null, "CVE-2020-15778", BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.9), LocalDate.now(), Instant.now());
        when(epssRepo.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(epss));
        when(kevRepo.existsByCveId("CVE-2020-15778")).thenReturn(true);

        mvc.perform(get("/api/risk/score").param("cve", "CVE-2020-15778").param("device", "42"))
            .andExpect(status().isOk());
    }
}
