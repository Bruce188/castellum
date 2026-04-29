package io.castellum.web;

import io.castellum.config.SecurityConfig;
import io.castellum.discovery.*;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(PassiveScanController.class)
@Import(SecurityConfig.class)
class PassiveScanControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private PassiveDiscoveryService service;

    @Test
    void post_validRequest_returnsResponseBody() throws Exception {
        when(service.sweep(any())).thenReturn(
            new PassiveDiscoveryResponse(2, List.of(1L, 2L), Map.of(DiscoverySource.ARP, 2)));

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
            new PassiveDiscoveryResponse(0, List.of(), Map.of()));

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
            new PassiveDiscoveryResponse(0, List.of(), Map.of()));

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
}
