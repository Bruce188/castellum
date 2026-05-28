package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.discovery.ActiveNetworkDetector;
import io.castellum.discovery.DiscoverySweepRepository;
import io.castellum.discovery.DiscoveryUnavailableException;
import io.castellum.discovery.DockerDiscoveryResponse;
import io.castellum.discovery.DockerDiscoveryService;
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
import java.util.List;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies {@code POST /api/discovery/docker}: ADMIN→200 with the discovered/updated count,
 * VIEWER→403, anon→401, and docker-unavailable→503 (mapped from
 * {@link DiscoveryUnavailableException} by {@link GlobalExceptionHandler}).
 */
@WebMvcTest(PassiveDiscoveryController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class,
    RbacAuthenticationEntryPoint.class, GlobalExceptionHandler.class,
    DockerDiscoveryEndpointTest.FixedClockConfig.class})
class DockerDiscoveryEndpointTest {

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        Clock clock() {
            return Clock.fixed(Instant.parse("2026-05-28T12:00:00Z"), ZoneOffset.UTC);
        }
    }

    @Autowired private MockMvc mockMvc;
    @MockBean private PassiveDiscoveryService service;
    @MockBean private DiscoverySweepRepository sweepRepository;
    @MockBean private AuditService auditService;
    @MockBean private CastellumUserDetailsService castellumUserDetailsService;
    @MockBean private JwtService jwtService;
    @MockBean private UserRepository userRepository;
    @MockBean private ActiveNetworkDetector activeNetworkDetector;
    @MockBean private DockerDiscoveryService dockerDiscoveryService;

    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_returns200WithCounts() throws Exception {
        when(dockerDiscoveryService.discover())
            .thenReturn(new DockerDiscoveryResponse(8, 2, 10, List.of(1L, 2L, 3L)));

        mockMvc.perform(post("/api/discovery/docker"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.containers").value(8))
            .andExpect(jsonPath("$.gateways").value(2))
            .andExpect(jsonPath("$.updated").value(10));
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_returns403() throws Exception {
        mockMvc.perform(post("/api/discovery/docker"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anon_returns401() throws Exception {
        mockMvc.perform(post("/api/discovery/docker").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void dockerUnavailable_returns503() throws Exception {
        when(dockerDiscoveryService.discover())
            .thenThrow(new DiscoveryUnavailableException("docker CLI unavailable: command not found"));

        mockMvc.perform(post("/api/discovery/docker"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.error").value("discovery_unavailable"));
    }
}
