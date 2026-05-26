package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import io.castellum.web.GlobalExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ScanPolicyController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class, GlobalExceptionHandler.class})
class ScanPolicyControllerTest {

    @Autowired private MockMvc mockMvc;
    @MockBean private ScanPolicyRepository repository;
    @MockBean private AuditService auditService;
    @MockBean private CastellumUserDetailsService castellumUserDetailsService;
    @MockBean private JwtService jwtService;
    @MockBean private UserRepository userRepository;

    private ScanPolicy stub(long id, String name) {
        ScanPolicy p = new ScanPolicy(name, "0 0 * * * *", "10.0.0.0/24", "PING_SWEEP", true);
        p.setId(id);
        return p;
    }

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_canCreate_returns201_andAudits() throws Exception {
        ScanPolicy saved = stub(7L, "hourly-lab");
        when(repository.findByName("hourly-lab")).thenReturn(Optional.empty());
        when(repository.save(any(ScanPolicy.class))).thenReturn(saved);

        mockMvc.perform(post("/api/scan-policy")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"hourly-lab\",\"cronExpression\":\"0 0 * * * *\","
                       + "\"cidr\":\"10.0.0.0/24\",\"scanType\":\"PING_SWEEP\",\"enabled\":true}"))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.id").value(7))
            .andExpect(jsonPath("$.name").value("hourly-lab"));

        verify(auditService).recordEvent(eq("admin"), eq("SCAN_POLICY_CREATE"), eq("scan_policy"),
            eq("7"), any());
    }

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_invalidCron_returns400() throws Exception {
        mockMvc.perform(post("/api/scan-policy")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"bad\",\"cronExpression\":\"not-a-cron\","
                       + "\"cidr\":\"10.0.0.0/24\",\"scanType\":\"PING_SWEEP\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_oversizeCidr_returns400_scopeTooLarge() throws Exception {
        mockMvc.perform(post("/api/scan-policy")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"too-big\",\"cronExpression\":\"0 0 * * * *\","
                       + "\"cidr\":\"10.0.0.0/16\",\"scanType\":\"PING_SWEEP\"}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("scope_too_large"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_canList() throws Exception {
        ScanPolicy a = stub(1L, "a"); ScanPolicy b = stub(2L, "b");
        Page<ScanPolicy> page = new PageImpl<>(List.of(a, b));
        when(repository.findAll(any(Pageable.class))).thenReturn(page);

        mockMvc.perform(get("/api/scan-policy"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content.length()").value(2))
            .andExpect(jsonPath("$.content[0].name").value("a"));
    }

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_disable_setsEnabledFalse_andAudits() throws Exception {
        ScanPolicy saved = stub(5L, "to-disable");
        when(repository.findById(5L)).thenReturn(Optional.of(saved));
        when(repository.save(any(ScanPolicy.class))).thenReturn(saved);

        mockMvc.perform(put("/api/scan-policy/5/disable"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.enabled").value(false));

        verify(auditService).recordEvent(eq("admin"), eq("SCAN_POLICY_UPDATE"), eq("scan_policy"),
            eq("5"), any());
    }

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_delete_returns204_andAudits() throws Exception {
        when(repository.existsById(9L)).thenReturn(true);
        mockMvc.perform(delete("/api/scan-policy/9"))
            .andExpect(status().isNoContent());
        verify(repository).deleteById(9L);
        verify(auditService).recordEvent(eq("admin"), eq("SCAN_POLICY_DELETE"), eq("scan_policy"),
            eq("9"), any());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_cannotCreate_returns403() throws Exception {
        mockMvc.perform(post("/api/scan-policy")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"x\",\"cronExpression\":\"0 0 * * * *\","
                       + "\"cidr\":\"10.0.0.0/24\",\"scanType\":\"PING_SWEEP\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_cannotList_returns403() throws Exception {
        mockMvc.perform(get("/api/scan-policy"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anon_returns401() throws Exception {
        mockMvc.perform(get("/api/scan-policy").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }
}
