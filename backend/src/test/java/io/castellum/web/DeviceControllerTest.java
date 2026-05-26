package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.discovery.DiscoveryScope;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.Criticality;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(DeviceController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class DeviceControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DeviceRepository deviceRepository;

    @MockBean
    private AuditService auditService;

    @MockBean
    private CastellumUserDetailsService castellumUserDetailsService;
    @MockBean
    JwtService jwtService;
    @MockBean
    UserRepository userRepository;

    @Test
    void getById_missingId_returns404() throws Exception {
        when(deviceRepository.findById(999L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/devices/999"))
            .andExpect(status().isNotFound());
    }

    @Test
    void post_validBody_returns201WithLocationHeader() throws Exception {
        Device saved = new Device();
        saved.setId(1L);
        saved.setIpAddress("192.168.1.1");

        when(deviceRepository.save(any(Device.class))).thenReturn(saved);

        mockMvc.perform(post("/api/devices")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ipAddress\":\"192.168.1.1\"}"))
            .andExpect(status().isCreated())
            .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("/api/devices/")));

        verify(auditService).recordEvent(eq("system"), eq("DEVICE_CREATE"), eq("device"), anyString(), any());
    }

    @Test
    void create_acceptsCriticalityField() throws Exception {
        Device saved = new Device();
        saved.setId(2L);
        saved.setIpAddress("10.0.0.1");
        saved.setCriticality(Criticality.HIGH);
        when(deviceRepository.save(any(Device.class))).thenReturn(saved);

        mockMvc.perform(post("/api/devices")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ipAddress\":\"10.0.0.1\",\"criticality\":\"HIGH\"}"))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.criticality").value("HIGH"));
    }

    @Test
    void create_defaultsToMediumWhenOmitted() throws Exception {
        Device saved = new Device();
        saved.setId(3L);
        saved.setIpAddress("10.0.0.2");
        saved.setCriticality(Criticality.MEDIUM);
        when(deviceRepository.save(any(Device.class))).thenReturn(saved);

        mockMvc.perform(post("/api/devices")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ipAddress\":\"10.0.0.2\"}"))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.criticality").value("MEDIUM"));
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCannotMutate_returns403() throws Exception {
        mockMvc.perform(post("/api/devices")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ipAddress\":\"10.0.0.99\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anon_returns401() throws Exception {
        mockMvc.perform(get("/api/devices").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void put_admin_updatesAndEmitsAudit() throws Exception {
        Device existing = new Device();
        existing.setId(7L);
        existing.setIpAddress("10.0.0.7");
        existing.setCriticality(Criticality.MEDIUM);
        when(deviceRepository.findById(7L)).thenReturn(Optional.of(existing));

        Device saved = new Device();
        saved.setId(7L);
        saved.setIpAddress("10.0.0.7");
        saved.setHostname("renamed-host");
        saved.setCriticality(Criticality.CRITICAL);
        when(deviceRepository.save(any(Device.class))).thenReturn(saved);

        mockMvc.perform(put("/api/devices/7")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ipAddress\":\"10.0.0.7\",\"hostname\":\"renamed-host\",\"criticality\":\"CRITICAL\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.hostname").value("renamed-host"))
            .andExpect(jsonPath("$.criticality").value("CRITICAL"));

        verify(auditService).recordEvent(eq("system"), eq("DEVICE_UPDATE"), eq("device"), eq("7"), any());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void put_viewer_returns403() throws Exception {
        mockMvc.perform(put("/api/devices/7")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ipAddress\":\"10.0.0.7\",\"criticality\":\"HIGH\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void delete_admin_removesAndEmitsAudit() throws Exception {
        Device existing = new Device();
        existing.setId(9L);
        existing.setIpAddress("10.0.0.9");
        existing.setCriticality(Criticality.LOW);
        when(deviceRepository.findById(9L)).thenReturn(Optional.of(existing));

        mockMvc.perform(delete("/api/devices/9"))
            .andExpect(status().isNoContent());

        verify(deviceRepository).deleteById(9L);
        verify(auditService).recordEvent(eq("system"), eq("DEVICE_DELETE"), eq("device"), eq("9"), any());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void delete_viewer_returns403() throws Exception {
        mockMvc.perform(delete("/api/devices/9"))
            .andExpect(status().isForbidden());
    }

    @Test
    void get_returnsDiscoveryScopeInPayload() throws Exception {
        Device existing = new Device();
        existing.setId(42L);
        existing.setIpAddress("172.17.0.2");
        existing.setCriticality(Criticality.MEDIUM);
        existing.setDiscoveryScope(DiscoveryScope.DOCKER_BRIDGE);
        when(deviceRepository.findById(42L)).thenReturn(Optional.of(existing));

        mockMvc.perform(get("/api/devices/42"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.discoveryScope").value("DOCKER_BRIDGE"));
    }
}
