package io.castellum.web;

import io.castellum.config.SecurityConfig;
import io.castellum.threatintel.ThreatIntelService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ThreatIntelController.class)
@Import(SecurityConfig.class)
class ThreatIntelControllerTest {

    @Autowired MockMvc mvc;
    @MockBean ThreatIntelService service;

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
}
