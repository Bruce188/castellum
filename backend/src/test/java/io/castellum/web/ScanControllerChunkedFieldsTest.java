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
import io.castellum.scan.ScanType;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Chunked wide-range scanning — new request/entity/DTO fields (4a + 4c backend half).
 *
 * <p>ScanRequest gains a nullable third component {@code skipHostDiscovery} (absent/null
 * means false); ScanController persists it onto the new Scan row. ScanDetailDto gains
 * {@code chunksTotal}/{@code chunksDone}, copied by the GET /api/scans/{id} mapping.
 */
@WebMvcTest(ScanController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class ScanControllerChunkedFieldsTest {

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

    /** ScanRequest's third component is nullable Boolean — null is a legal value. */
    @Test
    void scanRequest_acceptsNullSkipHostDiscovery() {
        ScanRequest request = new ScanRequest("10.0.0.0/24", ScanType.PING_SWEEP, null);
        assertNull(request.skipHostDiscovery());

        ScanRequest flagged = new ScanRequest("10.0.0.0/24", ScanType.PING_SWEEP, Boolean.TRUE);
        assertEquals(Boolean.TRUE, flagged.skipHostDiscovery());
    }

    @Test
    void postScan_skipHostDiscoveryTrue_persistedOnScanRow() throws Exception {
        when(scanRateLimiter.tryAcquire(anyString())).thenReturn(true);
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> {
            Scan s = inv.getArgument(0);
            s.setId(91L);
            return s;
        });

        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"203.0.113.0/24\",\"type\":\"SERVICE_DETECT\",\"skipHostDiscovery\":true}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.id").value(91));

        ArgumentCaptor<Scan> captor = ArgumentCaptor.forClass(Scan.class);
        verify(scanRepository).save(captor.capture());
        assertTrue(captor.getValue().isSkipHostDiscovery(),
            "skipHostDiscovery=true in the request must be persisted on the scan row");
    }

    @Test
    void postScan_flagAbsent_persistsFalse() throws Exception {
        when(scanRateLimiter.tryAcquire(anyString())).thenReturn(true);
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> {
            Scan s = inv.getArgument(0);
            s.setId(92L);
            return s;
        });

        // Existing two-field payload — Jackson leaves skipHostDiscovery null → false.
        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"192.168.1.0/24\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isAccepted());

        ArgumentCaptor<Scan> captor = ArgumentCaptor.forClass(Scan.class);
        verify(scanRepository).save(captor.capture());
        assertFalse(captor.getValue().isSkipHostDiscovery(),
            "absent skipHostDiscovery must persist as false");
    }

    @Test
    void getById_exposesChunkProgressFields() throws Exception {
        Scan scan = new Scan();
        scan.setId(8L);
        scan.setCidr("10.0.0.0/20");
        scan.setScanType("PING_SWEEP");
        scan.setStatus(ScanStatus.RUNNING);
        scan.setRequestedAt(Instant.parse("2026-01-01T00:00:00Z"));
        scan.setChunksTotal(4);
        scan.setChunksDone(2);

        when(scanRepository.findById(8L)).thenReturn(Optional.of(scan));
        when(deviceRepository.findIdsByLastSeenByScanId(8L)).thenReturn(List.of());

        mockMvc.perform(get("/api/scans/8"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(8))
            .andExpect(jsonPath("$.chunksTotal").value(4))
            .andExpect(jsonPath("$.chunksDone").value(2));
    }

    @Test
    void getById_legacyScanWithoutChunkData_exposesNulls() throws Exception {
        Scan scan = new Scan();
        scan.setId(9L);
        scan.setCidr("10.0.0.0/24");
        scan.setScanType("PING_SWEEP");
        scan.setStatus(ScanStatus.COMPLETE);
        scan.setRequestedAt(Instant.parse("2026-01-01T00:00:00Z"));
        scan.setCompletedAt(Instant.parse("2026-01-01T00:05:00Z"));

        when(scanRepository.findById(9L)).thenReturn(Optional.of(scan));
        when(deviceRepository.findIdsByLastSeenByScanId(9L)).thenReturn(List.of());

        mockMvc.perform(get("/api/scans/9"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.chunksTotal").value(nullValue()))
            .andExpect(jsonPath("$.chunksDone").value(nullValue()));
    }

    private static org.hamcrest.Matcher<Object> nullValue() {
        return org.hamcrest.Matchers.nullValue();
    }
}
