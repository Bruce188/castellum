package io.castellum.web;

import io.castellum.admin.InitialSyncService;
import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import io.castellum.web.dto.InitialSyncRequest;
import io.castellum.web.dto.InitialSyncResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AdminController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class AdminControllerTest {

    @Autowired MockMvc mvc;

    @MockBean InitialSyncService initialSyncService;
    @MockBean AuditService auditService;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean JwtService jwtService;
    @MockBean UserRepository userRepository;

    @Test
    void anonymousPost_returns401() throws Exception {
        mvc.perform(post("/api/admin/initial-sync")
                .with(anonymous())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerPost_returns403() throws Exception {
        mvc.perform(post("/api/admin/initial-sync")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void adminPost_emptyBody_returns202WithStatusStarted() throws Exception {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        when(initialSyncService.trigger(any(InitialSyncRequest.class), anyString()))
            .thenReturn(new InitialSyncResponse("started", now));

        mvc.perform(post("/api/admin/initial-sync")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.status").value("started"))
            .andExpect(jsonPath("$.startedAt").exists());
    }

    @Test
    void adminPost_explicitWindow_returns202() throws Exception {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        when(initialSyncService.trigger(any(InitialSyncRequest.class), anyString()))
            .thenReturn(new InitialSyncResponse("started", now));

        mvc.perform(post("/api/admin/initial-sync")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"since\":\"2024-01-01T00:00:00Z\",\"until\":\"2025-01-01T00:00:00Z\"}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.status").value("started"));
    }

    @Test
    void adminPost_auditsInitialSyncTriggeredBeforeDispatch() throws Exception {
        Instant now = Instant.now();
        when(initialSyncService.trigger(any(InitialSyncRequest.class), anyString()))
            .thenReturn(new InitialSyncResponse("started", now));

        mvc.perform(post("/api/admin/initial-sync")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isAccepted());

        verify(auditService).recordEvent(
            anyString(),
            eq("INITIAL_SYNC_TRIGGERED"),
            eq("initial-sync"),
            eq("global"),
            any());
    }

    // --- GET /api/admin/sync/status ---

    @Test
    void admin_getSyncStatus_returnsRunningFalseBaseline() throws Exception {
        when(initialSyncService.isInFlight()).thenReturn(false);
        when(initialSyncService.getStartedAt()).thenReturn(null);

        mvc.perform(get("/api/admin/sync/status"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.running").value(false))
            .andExpect(jsonPath("$.startedAt").doesNotExist());
    }

    @Test
    void admin_getSyncStatus_returnsRunningTrueWhenInFlight() throws Exception {
        Instant ts = Instant.parse("2026-05-26T00:00:00Z");
        when(initialSyncService.isInFlight()).thenReturn(true);
        when(initialSyncService.getStartedAt()).thenReturn(ts);

        mvc.perform(get("/api/admin/sync/status"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.running").value(true))
            .andExpect(jsonPath("$.startedAt").value("2026-05-26T00:00:00Z"));
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_getSyncStatus_returns403() throws Exception {
        mvc.perform(get("/api/admin/sync/status"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anonymous_getSyncStatus_returns401() throws Exception {
        mvc.perform(get("/api/admin/sync/status").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }
}
