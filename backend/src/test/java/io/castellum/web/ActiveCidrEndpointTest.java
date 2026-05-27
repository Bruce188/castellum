package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.discovery.ActiveNetworkDetector;
import io.castellum.discovery.ActiveNetworkDetector.ActiveNetwork;
import io.castellum.discovery.DiscoverySweepRepository;
import io.castellum.discovery.PassiveDiscoveryService;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies {@code GET /api/discovery/active-cidr} RBAC + JSON shape.
 * Uses a {@link MockBean} {@link ActiveNetworkDetector} — never touches real interfaces.
 */
@WebMvcTest(PassiveDiscoveryController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class,
    RbacAuthenticationEntryPoint.class, ActiveCidrEndpointTest.FixedClockConfig.class})
class ActiveCidrEndpointTest {

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        Clock clock() {
            return Clock.fixed(Instant.parse("2026-05-26T12:00:00Z"), ZoneOffset.UTC);
        }
    }

    @Autowired private MockMvc mockMvc;
    @MockBean private PassiveDiscoveryService service;
    @MockBean private DiscoverySweepRepository sweepRepository;
    @MockBean private AuditService auditService;
    @MockBean private CastellumUserDetailsService castellumUserDetailsService;
    @MockBean private JwtService jwtService;
    @MockBean private UserRepository userRepository;
    @MockBean private ActiveNetworkDetector detector;

    // -----------------------------------------------------------------------
    // Case 1 — anon → 401
    // -----------------------------------------------------------------------
    @Test
    void activeCidr_anon_returns401() throws Exception {
        mockMvc.perform(get("/api/discovery/active-cidr").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    // -----------------------------------------------------------------------
    // Case 2 — VIEWER → 200 (RBAC = VIEWER+ADMIN)
    // -----------------------------------------------------------------------
    @Test
    @WithMockUser(roles = "VIEWER")
    void activeCidr_viewer_returns200() throws Exception {
        when(detector.detect()).thenReturn(Optional.empty());
        mockMvc.perform(get("/api/discovery/active-cidr"))
            .andExpect(status().isOk());
    }

    // -----------------------------------------------------------------------
    // Case 3 — ADMIN → 200 with full shape
    // -----------------------------------------------------------------------
    @Test
    @WithMockUser(roles = "ADMIN")
    void activeCidr_admin_returnsFullShape() throws Exception {
        when(detector.detect()).thenReturn(Optional.of(
            new ActiveNetwork("eth6", "192.168.68.0/22", "192.168.68.51", 22, null)));

        mockMvc.perform(get("/api/discovery/active-cidr"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.iface").value("eth6"))
            .andExpect(jsonPath("$.cidr").value("192.168.68.0/22"))
            .andExpect(jsonPath("$.ipAddress").value("192.168.68.51"))
            .andExpect(jsonPath("$.prefix").value(22));
    }

    // -----------------------------------------------------------------------
    // Case 4 — empty detection → documented empty shape (HTTP 200, never 204)
    // -----------------------------------------------------------------------
    @Test
    @WithMockUser(roles = "ADMIN")
    void activeCidr_emptyDetection_returnsDocumentedEmptyShape() throws Exception {
        when(detector.detect()).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/discovery/active-cidr"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.iface").doesNotExist())
            .andExpect(jsonPath("$.cidr").doesNotExist())
            .andExpect(jsonPath("$.ipAddress").doesNotExist())
            .andExpect(jsonPath("$.prefix").value(0));
    }

    // -----------------------------------------------------------------------
    // Case 5 — clamp note surfaced
    // -----------------------------------------------------------------------
    @Test
    @WithMockUser(roles = "ADMIN")
    void activeCidr_clampNote_surfacedInResponse() throws Exception {
        String note = "Detected /16 narrowed to /22 (scan size cap) — adjust if needed.";
        when(detector.detect()).thenReturn(Optional.of(
            new ActiveNetwork("eth0", "192.168.0.0/22", "192.168.0.51", 22, note)));

        mockMvc.perform(get("/api/discovery/active-cidr"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.note").value(not(emptyOrNullString())));
    }
}
