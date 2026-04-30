package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import io.castellum.threatintel.ThreatIntelService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ThreatIntelController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class ThreatIntelControllerTest {

    @Autowired MockMvc mvc;
    @MockBean
    AuditService auditService;
    @MockBean ThreatIntelService service;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean
    JwtService jwtService;
    @MockBean UserRepository userRepository;

    @Test
    @WithMockUser(roles = "ADMIN")
    void export_returns200_andContentTypeJson() throws Exception {
        when(service.exportBundle()).thenReturn(
            new ThreatIntelService.ExportResult("bundle--abc", 3, "{\"type\":\"bundle\"}"));
        mvc.perform(post("/api/threat-intel/export"))
            .andExpect(status().isOk())
            .andExpect(content().contentType("application/json"))
            .andExpect(content().string("{\"type\":\"bundle\"}"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void pushTaxii_returns200_withDtoShape() throws Exception {
        when(service.pushTaxii(any())).thenReturn(
            new ThreatIntelService.TaxiiPushResult("bundle--abc", 5, 201));
        mvc.perform(post("/api/threat-intel/push/taxii"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("pushed"))
            .andExpect(jsonPath("$.objects").value(5))
            .andExpect(jsonPath("$.bundle_id").value("bundle--abc"))
            .andExpect(jsonPath("$.status_code").value(201));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void pushMisp_returns200_withDtoShape() throws Exception {
        when(service.pushMisp()).thenReturn(
            new ThreatIntelService.MispPushResult("bundle--abc", "42"));
        mvc.perform(post("/api/threat-intel/push/misp"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("pushed"))
            .andExpect(jsonPath("$.bundle_id").value("bundle--abc"))
            .andExpect(jsonPath("$.misp_event_id").value("42"));
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCannotMutate_returns403() throws Exception {
        mvc.perform(post("/api/threat-intel/export")
                .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isForbidden());
    }
}
