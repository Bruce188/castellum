package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(NetworkServiceController.class)
@Import(SecurityConfig.class)
class NetworkServiceControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private NetworkServiceRepository serviceRepository;

    @MockBean
    private AuditService auditService;

    @Test
    void post_portOutOfRange_returns400() throws Exception {
        mockMvc.perform(post("/api/services")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"deviceId\":1,\"port\":70000,\"protocol\":\"tcp\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void get_withDeviceId_invokesRepository() throws Exception {
        when(serviceRepository.findByDeviceId(42L)).thenReturn(List.of());

        mockMvc.perform(get("/api/services?deviceId=42"))
            .andExpect(status().isOk());

        verify(serviceRepository).findByDeviceId(42L);
    }

    @Test
    void post_validBody_auditsServiceCreate() throws Exception {
        NetworkService saved = new NetworkService();
        saved.setId(5L);
        saved.setDeviceId(1L);
        saved.setPort(8080);
        saved.setProtocol("tcp");

        when(serviceRepository.save(any(NetworkService.class))).thenReturn(saved);

        mockMvc.perform(post("/api/services")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"deviceId\":1,\"port\":8080,\"protocol\":\"tcp\"}"))
            .andExpect(status().isCreated());

        verify(auditService).recordEvent(eq("system"), eq("SERVICE_CREATE"), eq("service"), anyString(), any());
    }
}
