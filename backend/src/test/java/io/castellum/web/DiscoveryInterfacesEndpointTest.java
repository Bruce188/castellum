package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.discovery.ActiveNetworkDetector;
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

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies {@code GET /api/discovery/interfaces}: anon→401, viewer→403, admin→200.
 *
 * <p>The endpoint enumerates {@link java.net.NetworkInterface#getNetworkInterfaces()};
 * test only asserts shape (array, not null), not specific interface names — the host
 * running the test may have any combination of up, non-loopback NICs.
 */
@WebMvcTest(PassiveDiscoveryController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class,
    RbacAuthenticationEntryPoint.class, DiscoveryInterfacesEndpointTest.FixedClockConfig.class})
class DiscoveryInterfacesEndpointTest {

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
    @MockBean private ActiveNetworkDetector activeNetworkDetector;

    @Test
    void getInterfaces_anon_returns401() throws Exception {
        mockMvc.perform(get("/api/discovery/interfaces").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void getInterfaces_viewer_returns403() throws Exception {
        mockMvc.perform(get("/api/discovery/interfaces"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void getInterfaces_admin_returns200WithArray() throws Exception {
        mockMvc.perform(get("/api/discovery/interfaces"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());
    }
}
