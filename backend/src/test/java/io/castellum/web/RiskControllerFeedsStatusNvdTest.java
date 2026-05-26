package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.config.SecurityConfig;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkServiceRepository;
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

import java.time.Instant;
import java.time.LocalDate;
import java.util.Optional;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(RiskController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class RiskControllerFeedsStatusNvdTest {

    @Autowired MockMvc mvc;

    @MockBean AuditService auditService;
    @MockBean CveRepository cveRepo;
    @MockBean DeviceRepository deviceRepo;
    @MockBean EpssScoreRepository epssRepo;
    @MockBean KevEntryRepository kevRepo;
    @MockBean NetworkServiceRepository networkServiceRepository;
    @MockBean CveMatcher cveMatcher;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean JwtService jwtService;
    @MockBean UserRepository userRepository;

    @Test
    void feedsStatus_includesNvdRowCountAndLastModified() throws Exception {
        when(cveRepo.count()).thenReturn(42L);
        when(cveRepo.findMaxLastModified()).thenReturn(Optional.of(Instant.parse("2025-01-01T00:00:00Z")));
        when(epssRepo.count()).thenReturn(0L);
        when(epssRepo.findMaxScoreDate()).thenReturn(Optional.empty());
        when(kevRepo.count()).thenReturn(0L);
        when(kevRepo.findMaxIngestedAt()).thenReturn(Optional.empty());

        mvc.perform(get("/api/risk/feeds/status"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.nvd.rowCount").value(42))
            .andExpect(jsonPath("$.nvd.lastModified").value("2025-01-01T00:00:00Z"))
            .andExpect(jsonPath("$.epss").exists())
            .andExpect(jsonPath("$.kev").exists());
    }

    @Test
    void feedsStatus_nvdNullLastModified_serializesAsNull() throws Exception {
        when(cveRepo.count()).thenReturn(0L);
        when(cveRepo.findMaxLastModified()).thenReturn(Optional.empty());
        when(epssRepo.count()).thenReturn(0L);
        when(epssRepo.findMaxScoreDate()).thenReturn(Optional.of(LocalDate.now()));
        when(kevRepo.count()).thenReturn(0L);
        when(kevRepo.findMaxIngestedAt()).thenReturn(Optional.empty());

        mvc.perform(get("/api/risk/feeds/status"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.nvd.rowCount").value(0))
            .andExpect(jsonPath("$.nvd.lastModified").isEmpty());
    }
}
