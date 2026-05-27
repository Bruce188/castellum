package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
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

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// Tests GlobalExceptionHandler via real controllers — @RestControllerAdvice applies globally.
@WebMvcTest({DeviceController.class, NetworkServiceController.class})
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class, GlobalExceptionHandler.class})
@WithMockUser(roles = "ADMIN")
class GlobalExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DeviceRepository deviceRepository;

    @MockBean
    private NetworkServiceRepository serviceRepository;

    @MockBean
    private AuditService auditService;

    @MockBean
    private io.castellum.risk.RiskCacheEvictor riskCacheEvictor;

    @MockBean
    private CastellumUserDetailsService castellumUserDetailsService;
    @MockBean
    JwtService jwtService;
    @MockBean
    UserRepository userRepository;

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

    @Test
    @WithMockUser(roles = "VIEWER")
    void accessDenied_returns403() throws Exception {
        // VIEWER attempting POST /api/devices triggers @PreAuthorize → AccessDeniedException → 403
        mockMvc.perform(post("/api/devices")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ipAddress\":\"10.0.0.1\"}"))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.error").exists());
    }
}
