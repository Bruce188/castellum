package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Acceptance for the submit-endpoint scope boundary: anything wider than the
 * chunkable /16 ceiling → 400 with the scope_too_large body; /22 → 202.
 * (/20..../16 acceptance lives in ScanControllerChunkedScanTest.)
 */
@WebMvcTest(ScanController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class, GlobalExceptionHandler.class})
@WithMockUser(roles = "ADMIN")
class ScanScopeTooLargeTest {

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
    void slash15_returns400WithScopeTooLargeError() throws Exception {
        when(scanRateLimiter.tryAcquire(anyString())).thenReturn(true);
        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"10.0.0.0/15\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("scope_too_large"))
            .andExpect(jsonPath("$.prefix").value(15))
            .andExpect(jsonPath("$.maxAllowedPrefix").value(16));
    }

    @Test
    void slash22_succeedsWith202() throws Exception {
        when(scanRateLimiter.tryAcquire(anyString())).thenReturn(true);
        Scan saved = new Scan();
        saved.setId(123L);
        saved.setCidr("10.0.0.0/22");
        saved.setScanType("PING_SWEEP");
        saved.setStatus(ScanStatus.PENDING);
        when(scanRepository.save(any(Scan.class))).thenReturn(saved);

        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"10.0.0.0/22\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.id").value(123));
    }
}
