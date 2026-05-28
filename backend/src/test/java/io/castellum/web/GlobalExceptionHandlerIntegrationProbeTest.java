package io.castellum.web;

import io.castellum.config.SecurityConfig;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import io.castellum.threatintel.IntegrationProbeUnreachableException;
import io.castellum.threatintel.IntegrationProbeTimeoutException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Verifies that GlobalExceptionHandler maps the integration-probe exceptions
 * to the correct HTTP status codes and error slugs:
 *   IntegrationProbeUnreachableException -> 502  {"error":"integration_probe_unreachable"}
 *   IntegrationProbeTimeoutException     -> 504  {"error":"integration_probe_timeout"}
 *
 * Mirrors OtProbeControllerTest.probe_unreachable_returns502 /
 * probe_timeout_returns504 using a tiny inner stub @RestController.
 */
@WebMvcTest(GlobalExceptionHandlerIntegrationProbeTest.StubProbeController.class)
@Import({
    SecurityConfig.class,
    JwtAuthenticationFilter.class,
    RbacAccessDeniedHandler.class,
    RbacAuthenticationEntryPoint.class,
    GlobalExceptionHandler.class
})
@WithMockUser(roles = "ADMIN")
class GlobalExceptionHandlerIntegrationProbeTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CastellumUserDetailsService castellumUserDetailsService;
    @MockBean
    private JwtService jwtService;
    @MockBean
    private UserRepository userRepository;

    // ---------------------------------------------------------------------------
    // Stub controller — thin fixture that throws the new probe exceptions.
    // Has no production logic; exists solely to exercise GlobalExceptionHandler.
    // ---------------------------------------------------------------------------
    @RestController
    static class StubProbeController {

        @GetMapping("/test/integration-probe/unreachable")
        @PreAuthorize("hasRole('ADMIN')")
        public void throwUnreachable() {
            throw new IntegrationProbeUnreachableException("connection refused to stub host");
        }

        @GetMapping("/test/integration-probe/timeout")
        @PreAuthorize("hasRole('ADMIN')")
        public void throwTimeout() {
            throw new IntegrationProbeTimeoutException("read timeout from stub host");
        }
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    @Test
    void unreachable_exception_maps_to_502_with_integration_probe_unreachable_slug() throws Exception {
        mockMvc.perform(get("/test/integration-probe/unreachable")
                .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadGateway())
            .andExpect(jsonPath("$.error").value("integration_probe_unreachable"));
    }

    @Test
    void timeout_exception_maps_to_504_with_integration_probe_timeout_slug() throws Exception {
        mockMvc.perform(get("/test/integration-probe/timeout")
                .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isGatewayTimeout())
            .andExpect(jsonPath("$.error").value("integration_probe_timeout"));
    }
}
