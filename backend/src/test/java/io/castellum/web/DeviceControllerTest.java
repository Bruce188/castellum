package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(DeviceController.class)
@Import(SecurityConfig.class)
class DeviceControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DeviceRepository deviceRepository;

    @MockBean
    private AuditService auditService;

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
}
