package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.discovery.ActiveNetworkDetector;
import io.castellum.discovery.DockerDiscoveryService;
import io.castellum.discovery.DiscoverySweep;
import io.castellum.discovery.DiscoverySweepRepository;
import io.castellum.discovery.PassiveDiscoveryService;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(PassiveDiscoveryController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class,
    RbacAuthenticationEntryPoint.class, PassiveDiscoveryControllerSweepsTest.FixedClockConfig.class})
class PassiveDiscoveryControllerSweepsTest {

    static final Instant FIXED_NOW = Instant.parse("2026-04-30T12:00:00Z");

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        Clock clock() { return Clock.fixed(FIXED_NOW, ZoneOffset.UTC); }
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
    void getSweeps_anon_returns401() throws Exception {
        mockMvc.perform(get("/api/discovery/sweeps").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void getSweeps_viewer_returnsOrderedList() throws Exception {
        DiscoverySweep s1 = sample(1L, FIXED_NOW.minusSeconds(60), "OK", "ARP", 5, 5);
        DiscoverySweep s2 = sample(2L, FIXED_NOW.minusSeconds(120), "OK", "MDNS", 3, 3);
        when(sweepRepository.findByStartedAtAfterOrderByStartedAtDesc(any()))
            .thenReturn(List.of(s1, s2));

        mockMvc.perform(get("/api/discovery/sweeps"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0].id").value(1))
            .andExpect(jsonPath("$[0].source").value("ARP"))
            .andExpect(jsonPath("$[1].id").value(2));
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void getSweeps_invalidIso8601_returns400() throws Exception {
        mockMvc.perform(get("/api/discovery/sweeps").param("since", "not-a-date"))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void getSweeps_defaultSince_uses24hWindow() throws Exception {
        when(sweepRepository.findByStartedAtAfterOrderByStartedAtDesc(any()))
            .thenReturn(List.of());

        mockMvc.perform(get("/api/discovery/sweeps"))
            .andExpect(status().isOk());

        ArgumentCaptor<Instant> captor = ArgumentCaptor.forClass(Instant.class);
        verify(sweepRepository).findByStartedAtAfterOrderByStartedAtDesc(captor.capture());
        // Cutoff = FIXED_NOW − 24h
        assertThat(captor.getValue()).isEqualTo(FIXED_NOW.minus(java.time.Duration.ofHours(24)));
    }

    private DiscoverySweep sample(Long id, Instant startedAt, String status, String source,
                                  int neighborCount, int deviceCount) {
        DiscoverySweep s = new DiscoverySweep();
        s.setId(id);
        s.setStartedAt(startedAt);
        s.setFinishedAt(startedAt.plusSeconds(10));
        s.setSource(source);
        s.setIface("eth0");
        s.setNeighborCount(neighborCount);
        s.setDeviceCount(deviceCount);
        s.setTriggeredBy("MANUAL");
        s.setAuditLogId(99L);
        s.setStatus(status);
        return s;
    }
}
