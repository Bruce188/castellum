package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.ScanRepository;
import io.castellum.scan.ScanExecutionService;
import io.castellum.scan.ScanReportService;
import io.castellum.scan.ScanSubmissionRateLimiter;
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

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Acceptance for AC2: 21st submission in the window returns 429 + Retry-After.
 */
@WebMvcTest(ScanController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class, GlobalExceptionHandler.class})
@WithMockUser(roles = "ADMIN", username = "admin")
class ScanRateLimitTest {

    @Autowired private MockMvc mockMvc;
    @MockBean private ScanRepository scanRepository;
    @MockBean private AuditService auditService;
    @MockBean private ScanExecutionService scanExecutionService;
    @MockBean private ScanSubmissionRateLimiter scanRateLimiter;
    @MockBean private DeviceRepository deviceRepository;
    @MockBean private ScanReportService scanReportService;
    @MockBean private CastellumUserDetailsService castellumUserDetailsService;
    @MockBean private JwtService jwtService;
    @MockBean private UserRepository userRepository;

    @Test
    void overBudgetSubmission_returns429WithRetryAfterHeader() throws Exception {
        when(scanRateLimiter.tryAcquire(anyString())).thenReturn(false);
        when(scanRateLimiter.retryAfterSeconds(anyString())).thenReturn(1234L);

        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"10.0.0.0/24\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isTooManyRequests())
            .andExpect(header().string("Retry-After", "1234"));

        verify(auditService).recordEvent(eq("admin"), eq("SCAN_RATE_LIMIT"), eq("scan"),
            anyString(), any());
    }
}
