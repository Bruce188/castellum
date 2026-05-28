package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.discovery.ActiveNetworkDetector;
import io.castellum.discovery.DockerDiscoveryService;
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
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies {@code GET /api/discovery/sources}: anon→401, viewer→200 with the configured
 * source list. PCAP/LLDP/CDP {@code enabled} flags reflect the {@code castellum.discovery.*.enabled}
 * properties at request time.
 */
@WebMvcTest(PassiveDiscoveryController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class,
    RbacAuthenticationEntryPoint.class, PassiveDiscoveryControllerSourcesTest.FixedClockConfig.class})
@TestPropertySource(properties = {
    "castellum.discovery.pcap.enabled=false",
    "castellum.discovery.lldp.enabled=false",
    "castellum.discovery.cdp.enabled=false"
})
class PassiveDiscoveryControllerSourcesTest {

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        Clock clock() {
            return Clock.fixed(Instant.parse("2026-04-30T12:00:00Z"), ZoneOffset.UTC);
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
    void getSources_anon_returns401() throws Exception {
        mockMvc.perform(get("/api/discovery/sources").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void getSources_viewer_returnsConfiguredList() throws Exception {
        mockMvc.perform(get("/api/discovery/sources"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0].source").value("ARP"))
            .andExpect(jsonPath("$[0].enabled").value(true))
            .andExpect(jsonPath("$[1].source").value("MDNS"))
            .andExpect(jsonPath("$[1].enabled").value(true))
            .andExpect(jsonPath("$[2].source").value("PCAP"))
            .andExpect(jsonPath("$[2].enabled").value(false))
            .andExpect(jsonPath("$[3].source").value("LLDP"))
            .andExpect(jsonPath("$[3].enabled").value(false))
            .andExpect(jsonPath("$[4].source").value("CDP"))
            .andExpect(jsonPath("$[4].enabled").value(false));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void getSources_admin_returns200() throws Exception {
        // ADMIN explicitly granted access alongside VIEWER on /sources and /sweeps
        // (commit e863c6f: discovery endpoints use hasAnyRole('VIEWER','ADMIN')).
        mockMvc.perform(get("/api/discovery/sources"))
            .andExpect(status().isOk());
    }
}
