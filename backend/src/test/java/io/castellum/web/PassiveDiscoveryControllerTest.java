package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.discovery.*;
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
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(PassiveDiscoveryController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class, PassiveDiscoveryControllerTest.FixedClockConfig.class})
@WithMockUser(roles = "ADMIN")
class PassiveDiscoveryControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @MockBean
    AuditService auditService;

    @MockBean
    private PassiveDiscoveryService service;

    @MockBean
    private CastellumUserDetailsService castellumUserDetailsService;
    @MockBean
    JwtService jwtService;
    @MockBean
    UserRepository userRepository;
    @MockBean
    DiscoverySweepRepository sweepRepository;
    @MockBean
    ActiveNetworkDetector activeNetworkDetector;
    @MockBean
    DockerDiscoveryService dockerDiscoveryService;

    @org.springframework.boot.test.context.TestConfiguration
    static class FixedClockConfig {
        @org.springframework.context.annotation.Bean
        java.time.Clock clock() {
            return java.time.Clock.fixed(
                java.time.Instant.parse("2026-04-30T12:00:00Z"),
                java.time.ZoneOffset.UTC);
        }
    }

    @Test
    void post_validRequest_returnsResponseBody() throws Exception {
        when(service.sweep(any())).thenReturn(
            new PassiveDiscoveryResponse(2, List.of(1L, 2L), Map.of(DiscoverySource.ARP, 2), 42L));

        mockMvc.perform(post("/api/discovery/passive")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"iface":"eth0","durationSeconds":30,"sources":["ARP"]}
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.discovered").value(2));
    }

    @Test
    void post_invalidIfaceRegex_returns400() throws Exception {
        mockMvc.perform(post("/api/discovery/passive")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"iface":"eth0; rm -rf /","durationSeconds":30,"sources":["ARP"]}
                    """))
            .andExpect(status().isBadRequest());
    }

    @Test
    void post_durationOverMax_returns400() throws Exception {
        mockMvc.perform(post("/api/discovery/passive")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"iface":"eth0","durationSeconds":301,"sources":["ARP"]}
                    """))
            .andExpect(status().isBadRequest());
    }

    @Test
    void post_emptySources_defaultsToArpAndMdns() throws Exception {
        when(service.sweep(any())).thenReturn(
            new PassiveDiscoveryResponse(0, List.of(), Map.of(), null));

        mockMvc.perform(post("/api/discovery/passive")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"iface":"eth0","durationSeconds":30,"sources":[]}
                    """))
            .andExpect(status().isOk());

        ArgumentCaptor<PassiveDiscoveryRequest> captor =
            ArgumentCaptor.forClass(PassiveDiscoveryRequest.class);
        verify(service).sweep(captor.capture());
        assertThat(captor.getValue().sources())
            .containsExactlyInAnyOrder(DiscoverySource.ARP, DiscoverySource.MDNS);
    }

    @Test
    void post_pcapWithoutIface_returns503() throws Exception {
        when(service.sweep(any()))
            .thenThrow(new DiscoveryUnavailableException("PCAP source requires interface name"));

        mockMvc.perform(post("/api/discovery/passive")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"durationSeconds":30,"sources":["PCAP"]}
                    """))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.error").value("discovery_unavailable"));
    }

    @Test
    void post_omitsDuration_defaultsTo30() throws Exception {
        when(service.sweep(any())).thenReturn(
            new PassiveDiscoveryResponse(0, List.of(), Map.of(), null));

        mockMvc.perform(post("/api/discovery/passive")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"iface":"eth0","sources":["ARP"]}
                    """))
            .andExpect(status().isOk());

        ArgumentCaptor<PassiveDiscoveryRequest> captor =
            ArgumentCaptor.forClass(PassiveDiscoveryRequest.class);
        verify(service).sweep(captor.capture());
        assertThat(captor.getValue().durationSeconds()).isEqualTo(30);
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCannotMutate_returns403() throws Exception {
        mockMvc.perform(post("/api/discovery/passive")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"iface\":\"eth0\",\"durationSeconds\":10,\"sources\":[\"ARP\"]}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anon_returns401() throws Exception {
        mockMvc.perform(post("/api/discovery/passive")
                .with(anonymous())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isUnauthorized());
    }
}
