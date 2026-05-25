package io.castellum.web;

import io.castellum.admin.InitialSyncService;
import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.cve.NvdSyncService;
import io.castellum.risk.EpssIngestionService;
import io.castellum.risk.KevIngestionService;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Acceptance spec-tracer for {@code POST /api/admin/initial-sync}.
 *
 * <p>Covers AC#1a (ADMIN 202), AC#1b (VIEWER 403), AC#1c (anonymous 401),
 * AC#2 surrogate (services invoked once), and AC#4 (already-running returns 202).
 *
 * <p>Heavy assertions (per-feed failure isolation, finally-clear of inFlight, executor
 * wiring) live in {@link InitialSyncServiceTest} and {@link InitialSyncServiceIntegrationTest}.
 * This class is a thin spec-tracer so a single grep for AC#1 / AC#2 / AC#4 lands here.
 */
@WebMvcTest(AdminController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class AdminControllerAcceptanceTest {

    @Autowired MockMvc mvc;

    @MockBean InitialSyncService initialSyncService;
    @MockBean AuditService auditService;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean JwtService jwtService;
    @MockBean UserRepository userRepository;

    private static final Instant STARTED_AT = Instant.parse("2026-01-01T00:00:00Z");

    // ── AC#1a — ADMIN gets 202 + body ─────────────────────────────────────────

    @Test
    void ac1a_adminPost_returns202WithStartedStatus() throws Exception {
        when(initialSyncService.trigger(any(InitialSyncRequest.class), anyString()))
            .thenReturn(new InitialSyncResponse("started", STARTED_AT));

        mvc.perform(post("/api/admin/initial-sync")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.status").value("started"))
            .andExpect(jsonPath("$.startedAt").value("2026-01-01T00:00:00Z"));
    }

    // ── AC#1b — VIEWER gets 403 ────────────────────────────────────────────────

    @Test
    @WithMockUser(roles = "VIEWER")
    void ac1b_viewerPost_returns403() throws Exception {
        mvc.perform(post("/api/admin/initial-sync")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isForbidden());
    }

    // ── AC#1c — anonymous gets 401 ────────────────────────────────────────────

    @Test
    void ac1c_anonymousPost_returns401() throws Exception {
        mvc.perform(post("/api/admin/initial-sync")
                .with(anonymous())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            // JWT filter returns 401 for missing/invalid token; documented here.
            .andExpect(status().isUnauthorized());
    }

    // ── AC#2 surrogate — three downstream services invoked exactly once ────────
    // (Full async verification is in InitialSyncServiceIntegrationTest;
    //  this slice asserts the service method is called via the controller.)

    @Test
    void ac2_surrogate_initialSyncServiceTriggerCalledOnce() throws Exception {
        when(initialSyncService.trigger(any(InitialSyncRequest.class), anyString()))
            .thenReturn(new InitialSyncResponse("started", STARTED_AT));

        mvc.perform(post("/api/admin/initial-sync")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isAccepted());

        verify(initialSyncService, times(1)).trigger(any(InitialSyncRequest.class), anyString());
    }

    // ── AC#4 — second click while in-flight returns 202 already-running ──────
    // Design choice: 202 with status:"already-running" (not 409) per analysis-v23 Open Questions.
    // Simpler client logic: always treat non-error 2xx as "request acknowledged".

    @Test
    void ac4_secondClickWhileInFlight_returns202AlreadyRunning_withSameStartedAt() throws Exception {
        // Both calls return the same startedAt — simulating the in-flight guard
        when(initialSyncService.trigger(any(InitialSyncRequest.class), anyString()))
            .thenReturn(new InitialSyncResponse("already-running", STARTED_AT));

        mvc.perform(post("/api/admin/initial-sync")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.status").value("already-running"))
            .andExpect(jsonPath("$.startedAt").value("2026-01-01T00:00:00Z"));
    }
}
