package io.castellum.threatintel;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.security.AesGcmCipher;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import io.castellum.web.GlobalExceptionHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.mockito.Mockito.doThrow;

@WebMvcTest(IntegrationConfigController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class,
         RbacAuthenticationEntryPoint.class, GlobalExceptionHandler.class})
class IntegrationConfigControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockBean private IntegrationConfigRepository repository;
    @MockBean private AesGcmCipher cipher;
    @MockBean private ThreatIntelService threatIntelService;
    @MockBean private AuditService auditService;
    @MockBean private CastellumUserDetailsService castellumUserDetailsService;
    @MockBean private JwtService jwtService;
    @MockBean private UserRepository userRepository;
    @MockBean private IntegrationProbeService probeService;

    @BeforeEach
    void resetCipher() {
        // The cipher is mocked; tests stub encrypt/decrypt explicitly where used.
    }

    private IntegrationConfig stub(long id, String type) {
        IntegrationConfig c = new IntegrationConfig(type, "{\"url\":\"https://taxii.example/api/v21\"}",
            new byte[]{1, 2, 3, 4});
        c.setId(id);
        c.setCreatedAt(Instant.now());
        c.setUpdatedAt(Instant.now());
        return c;
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_getMissingType_returns404() throws Exception {
        when(repository.findByIntegrationType("TAXII")).thenReturn(Optional.empty());
        mockMvc.perform(get("/api/integrations/TAXII"))
            .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_getReturnsConfigWithoutCredentialBytes() throws Exception {
        when(repository.findByIntegrationType("TAXII")).thenReturn(Optional.of(stub(1L, "TAXII")));
        mockMvc.perform(get("/api/integrations/TAXII"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.integrationType").value("TAXII"))
            .andExpect(jsonPath("$.credentialsSet").value(true))
            // The encrypted bytes must never appear in the response JSON.
            .andExpect(jsonPath("$.encryptedCredentials").doesNotExist());
    }

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_putCreatesNewConfig_andAudits() throws Exception {
        when(repository.findByIntegrationType("TAXII")).thenReturn(Optional.empty());
        when(cipher.encrypt(anyString())).thenReturn(new byte[]{9, 9, 9});
        IntegrationConfig saved = stub(42L, "TAXII");
        when(repository.save(any(IntegrationConfig.class))).thenReturn(saved);

        mockMvc.perform(put("/api/integrations/TAXII")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"config\":{\"url\":\"https://taxii.example\",\"collectionId\":\"abc-123\"}," +
                         "\"credentials\":\"super-secret\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.integrationType").value("TAXII"));

        verify(cipher).encrypt("super-secret");
        verify(auditService).recordEvent(eq("admin"), eq("INTEGRATION_CONFIG_SAVE"),
            eq("integration_config"), anyString(), any());
    }

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_putUpdatesExistingConfig() throws Exception {
        IntegrationConfig existing = stub(7L, "MISP");
        when(repository.findByIntegrationType("MISP")).thenReturn(Optional.of(existing));
        when(cipher.encrypt(anyString())).thenReturn(new byte[]{0x10, 0x20});
        when(repository.save(any(IntegrationConfig.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(put("/api/integrations/MISP")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"config\":{\"url\":\"https://misp.example\"},\"credentials\":\"api-key-1\"}"))
            .andExpect(status().isOk());

        verify(cipher).encrypt("api-key-1");
        verify(repository).save(any(IntegrationConfig.class));
    }

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_pushTaxii_successSetsLastPushStatus_andAudits() throws Exception {
        IntegrationConfig cfg = stub(11L, "TAXII");
        when(repository.findByIntegrationType("TAXII")).thenReturn(Optional.of(cfg));
        when(cipher.decrypt(any(byte[].class))).thenReturn("pwd");
        when(threatIntelService.pushTaxii(any()))
            .thenReturn(new ThreatIntelService.TaxiiPushResult("bundle--abc", 7, 202));
        when(repository.save(any(IntegrationConfig.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/api/integrations/TAXII/push"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("ok"))
            .andExpect(jsonPath("$.bundleId").value("bundle--abc"))
            .andExpect(jsonPath("$.lastPushStatus").value(org.hamcrest.Matchers.startsWith("SUCCESS")));

        verify(auditService).recordEvent(eq("admin"), eq("TAXII_PUSH"),
            eq("integration_config"), anyString(), any());
    }

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_pushMisp_successSetsLastPushStatus_andAudits() throws Exception {
        IntegrationConfig cfg = stub(12L, "MISP");
        when(repository.findByIntegrationType("MISP")).thenReturn(Optional.of(cfg));
        when(cipher.decrypt(any(byte[].class))).thenReturn("api-key");
        when(threatIntelService.pushMisp())
            .thenReturn(new ThreatIntelService.MispPushResult("bundle--def", "evt-99"));
        when(repository.save(any(IntegrationConfig.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/api/integrations/MISP/push"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("ok"))
            .andExpect(jsonPath("$.lastPushStatus").value(org.hamcrest.Matchers.containsString("evt-99")));

        verify(auditService).recordEvent(eq("admin"), eq("MISP_PUSH"),
            eq("integration_config"), anyString(), any());
    }

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_pushFailure_setsErrorStatus_andAuditsError() throws Exception {
        IntegrationConfig cfg = stub(13L, "TAXII");
        when(repository.findByIntegrationType("TAXII")).thenReturn(Optional.of(cfg));
        when(cipher.decrypt(any(byte[].class))).thenReturn("pwd");
        when(threatIntelService.pushTaxii(any()))
            .thenThrow(new IOException("connection refused"));
        when(repository.save(any(IntegrationConfig.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/api/integrations/TAXII/push"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("error"))
            .andExpect(jsonPath("$.lastPushStatus").value(org.hamcrest.Matchers.containsString("connection refused")));

        verify(auditService).recordEvent(eq("admin"), eq("TAXII_PUSH"),
            eq("integration_config"), anyString(), any());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_pushMissingConfig_returns404() throws Exception {
        when(repository.findByIntegrationType("MISP")).thenReturn(Optional.empty());
        mockMvc.perform(post("/api/integrations/MISP/push"))
            .andExpect(status().isNotFound());
        verify(threatIntelService, never()).pushMisp();
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_unsupportedType_returns400() throws Exception {
        mockMvc.perform(get("/api/integrations/SLACK"))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_cannotGet_returns403() throws Exception {
        mockMvc.perform(get("/api/integrations/TAXII"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_cannotPut_returns403() throws Exception {
        mockMvc.perform(put("/api/integrations/TAXII")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"config\":{},\"credentials\":\"x\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_cannotPush_returns403() throws Exception {
        mockMvc.perform(post("/api/integrations/TAXII/push"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anon_get_returns401() throws Exception {
        mockMvc.perform(get("/api/integrations/TAXII").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    // ---- Probe endpoint tests (Task 1.3) ----

    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_probeReachable_returns200() throws Exception {
        when(probeService.probe(any(), any(), any()))
            .thenReturn(new IntegrationProbeDto.ProbeResult(true, "ok"));

        mockMvc.perform(post("/api/integrations/TAXII/probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"http://localhost:9000/\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.reachable").value(true));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_probeUnreachable_returns502() throws Exception {
        when(probeService.probe(any(), any(), any()))
            .thenThrow(new IntegrationProbeUnreachableException("connection refused"));

        mockMvc.perform(post("/api/integrations/TAXII/probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"http://localhost:9000/\"}"))
            .andExpect(status().isBadGateway())
            .andExpect(jsonPath("$.error").value("integration_probe_unreachable"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_probeTimeout_returns504() throws Exception {
        when(probeService.probe(any(), any(), any()))
            .thenThrow(new IntegrationProbeTimeoutException("read timeout"));

        mockMvc.perform(post("/api/integrations/TAXII/probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"http://localhost:9000/\"}"))
            .andExpect(status().isGatewayTimeout())
            .andExpect(jsonPath("$.error").value("integration_probe_timeout"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_probeBlankUrl_returns400() throws Exception {
        mockMvc.perform(post("/api/integrations/TAXII/probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_probeUnsupportedType_returns400() throws Exception {
        mockMvc.perform(post("/api/integrations/SLACK/probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"http://localhost:9000/\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_cannotProbe_returns403() throws Exception {
        mockMvc.perform(post("/api/integrations/TAXII/probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"http://localhost:9000/\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anon_probe_returns401() throws Exception {
        mockMvc.perform(post("/api/integrations/TAXII/probe")
                .with(anonymous())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"http://localhost:9000/\"}"))
            .andExpect(status().isUnauthorized());
    }
}
