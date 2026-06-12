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

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Chunked wide-range scanning — intake contract (4a).
 *
 * <p>POST /api/scan now sizes requests with the CHUNKABLE policy: CIDRs down to /16
 * are accepted (they will be executed as sequential /22 chunks), while anything wider
 * than /16 is still rejected with {@code scope_too_large} — and the rejection message
 * names the /16 ceiling that applies to chunked scans, not the strict /22 bound.
 */
@WebMvcTest(ScanController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class ScanControllerChunkedScanTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ScanRepository scanRepository;

    @MockBean
    private AuditService auditService;

    @MockBean
    private ScanExecutionService scanExecutionService;

    @MockBean
    private ScanSubmissionRateLimiter scanRateLimiter;

    @MockBean
    private DeviceRepository deviceRepository;

    @MockBean
    private ScanReportService scanReportService;

    @MockBean
    private CastellumUserDetailsService castellumUserDetailsService;
    @MockBean
    JwtService jwtService;
    @MockBean
    UserRepository userRepository;

    /**
     * A /20 (4096 hosts) is now accepted: it is within the chunkable ceiling and will be
     * executed as four /22 chunks. Pre-feature behavior (400 scope_too_large) must be gone.
     * Multi-chunk scans dispatch on the dedicated wide-scan lane (executeWideAsync), never
     * the interactive pool.
     */
    @Test
    void postScan_slash20_accepted202WithId_dispatchesWideLane() throws Exception {
        Scan saved = new Scan();
        saved.setId(77L);
        saved.setCidr("10.0.0.0/20");
        saved.setScanType("PING_SWEEP");
        saved.setStatus(ScanStatus.PENDING);

        when(scanRepository.save(any(Scan.class))).thenReturn(saved);
        when(scanRateLimiter.tryAcquire(anyString())).thenReturn(true);

        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"10.0.0.0/20\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.id").value(77));

        verify(auditService).recordEvent(anyString(), eq("SCAN_SUBMIT"), eq("scan"), anyString(), any());
        verify(scanExecutionService).executeWideAsync(saved.getId());
        verify(scanExecutionService, never()).executeAsync(any());
    }

    /**
     * A /16 (65536 hosts) is the chunkable boundary — accepted, not rejected, and routed
     * to the wide-scan lane (64 sequential chunks must never occupy the interactive pool).
     */
    @Test
    void postScan_slash16_acceptedBoundary_dispatchesWideLane() throws Exception {
        Scan saved = new Scan();
        saved.setId(78L);
        saved.setCidr("10.0.0.0/16");
        saved.setScanType("PING_SWEEP");
        saved.setStatus(ScanStatus.PENDING);

        when(scanRepository.save(any(Scan.class))).thenReturn(saved);
        when(scanRateLimiter.tryAcquire(anyString())).thenReturn(true);

        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"10.0.0.0/16\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.id").value(78));

        verify(scanExecutionService).executeWideAsync(saved.getId());
        verify(scanExecutionService, never()).executeAsync(any());
    }

    /**
     * A /24 is a single chunk — it stays on the interactive scanTaskExecutor lane and
     * must never be routed to the wide-scan lane.
     */
    @Test
    void postScan_slash24_singleChunk_dispatchesInteractiveLane() throws Exception {
        Scan saved = new Scan();
        saved.setId(79L);
        saved.setCidr("192.168.1.0/24");
        saved.setScanType("PING_SWEEP");
        saved.setStatus(ScanStatus.PENDING);

        when(scanRepository.save(any(Scan.class))).thenReturn(saved);
        when(scanRateLimiter.tryAcquire(anyString())).thenReturn(true);

        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"192.168.1.0/24\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.id").value(79));

        verify(scanExecutionService).executeAsync(saved.getId());
        verify(scanExecutionService, never()).executeWideAsync(any());
    }

    /**
     * A /15 is wider than the chunkable ceiling: 400 scope_too_large, no row persisted,
     * and the message must reference the /16 ceiling that governs chunked scans.
     */
    @Test
    void postScan_slash15_rejected400_messageNamesSlash16Ceiling() throws Exception {
        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"10.0.0.0/15\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("scope_too_large"))
            .andExpect(jsonPath("$.message", containsString("/16")));

        verify(scanRepository, never()).save(any());
        verify(scanExecutionService, never()).executeAsync(any());
        verify(scanExecutionService, never()).executeWideAsync(any());
    }
}
