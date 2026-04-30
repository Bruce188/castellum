package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
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
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(CveController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class CveControllerTest {

    @Autowired
    MockMvc mockMvc;
    @MockBean
    AuditService auditService;

    @MockBean
    CveRepository cveRepository;

    @MockBean
    CveMatcher cveMatcher;

    @MockBean
    CastellumUserDetailsService castellumUserDetailsService;
    @MockBean
    JwtService jwtService;
    @MockBean
    UserRepository userRepository;

    private Cve buildCve(String cveId) {
        Cve cve = new Cve();
        cve.setCveId(cveId);
        cve.setLastModified(Instant.parse("2023-11-07T03:18:00.640Z"));
        cve.setRawJson("{}");
        cve.setFetchedAt(Instant.now());
        return cve;
    }

    @Test
    void getByCveId_existingRecord_returns200WithBody() throws Exception {
        Cve cve = buildCve("CVE-2020-15778");
        when(cveRepository.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(cve));

        mockMvc.perform(get("/api/cve/CVE-2020-15778")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.cveId").value("CVE-2020-15778"));
    }

    @Test
    void getByCveId_missingRecord_returns404() throws Exception {
        when(cveRepository.findByCveId("CVE-9999-9999")).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/cve/CVE-9999-9999")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isNotFound());
    }

    @Test
    void findByCpe_invokesMatcher_andReturnsJson() throws Exception {
        String cpe = "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*";
        Cve cve = buildCve("CVE-2020-15778");
        when(cveMatcher.findVulnerable(cpe)).thenReturn(List.of(cve));

        mockMvc.perform(get("/api/cve")
                .param("cpe", cpe)
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0].cveId").value("CVE-2020-15778"));

        verify(cveMatcher).findVulnerable(eq(cpe));
    }
}
