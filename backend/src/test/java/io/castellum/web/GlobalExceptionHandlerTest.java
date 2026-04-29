package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// Tests GlobalExceptionHandler via real controllers — @RestControllerAdvice applies globally.
@WebMvcTest({DeviceController.class, NetworkServiceController.class})
@Import({SecurityConfig.class, GlobalExceptionHandler.class})
class GlobalExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DeviceRepository deviceRepository;

    @MockBean
    private NetworkServiceRepository serviceRepository;

    @MockBean
    private AuditService auditService;

    @Test
    void methodArgumentNotValid_returns400WithErrorBody() throws Exception {
        // POST with invalid port triggers MethodArgumentNotValidException
        mockMvc.perform(post("/api/services")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"deviceId\":1,\"port\":70000,\"protocol\":\"tcp\"}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void noSuchElementException_returns404WithErrorBody() throws Exception {
        when(deviceRepository.findById(999L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/devices/999"))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.error").exists());
    }
}
