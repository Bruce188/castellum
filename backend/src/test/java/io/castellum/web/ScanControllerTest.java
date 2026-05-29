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
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ScanController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class ScanControllerTest {

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

    @Test
    void postScan_validRequest_returns202WithId() throws Exception {
        Scan saved = new Scan();
        saved.setId(42L);
        saved.setCidr("192.168.1.0/24");
        saved.setScanType("PING_SWEEP");
        saved.setStatus(ScanStatus.PENDING);

        when(scanRepository.save(any(Scan.class))).thenReturn(saved);
        when(scanRateLimiter.tryAcquire(anyString())).thenReturn(true);

        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"192.168.1.0/24\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.id").value(42));

        verify(auditService).recordEvent(anyString(), eq("SCAN_SUBMIT"), eq("scan"), anyString(), any());
        verify(scanExecutionService).executeAsync(saved.getId());
    }

    @Test
    void postScan_invalidCidr_returns400() throws Exception {
        when(scanRateLimiter.tryAcquire(anyString())).thenReturn(true);
        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"not-a-cidr\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void postScan_invalidType_returns400() throws Exception {
        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"192.168.1.0/24\",\"type\":\"INVALID_TYPE\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void list_returnsPaginatedShape() throws Exception {
        when(scanRepository.findAll(any(Pageable.class))).thenReturn(Page.empty());
        mockMvc.perform(get("/api/scans"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content").exists())
            .andExpect(jsonPath("$.totalElements").exists());
    }

    @Test
    void list_respectsPageSize() throws Exception {
        when(scanRepository.findAll(any(Pageable.class))).thenReturn(Page.empty());
        mockMvc.perform(get("/api/scans?size=5&page=0"))
            .andExpect(status().isOk());
        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        verify(scanRepository).findAll(captor.capture());
        assertEquals(5, captor.getValue().getPageSize());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCannotMutate_returns403() throws Exception {
        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"10.0.0.0/24\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anon_returns401() throws Exception {
        mockMvc.perform(get("/api/scans").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    /**
     * AC1: getById now uses precise attribution via findIdsByLastSeenByScanId, not
     * the time-window heuristic findIdsByFirstSeenBetween.
     */
    @Test
    void getById_existingScan_returnsScanDetailDtoWithDiscoveredDeviceIds() throws Exception {
        Scan scan = new Scan();
        scan.setId(7L);
        scan.setCidr("10.0.0.0/24");
        scan.setScanType("PING_SWEEP");
        scan.setStatus(ScanStatus.COMPLETE);
        scan.setRequestedAt(Instant.parse("2024-01-01T00:00:00Z"));
        scan.setCompletedAt(Instant.parse("2024-01-01T00:05:00Z"));

        when(scanRepository.findById(7L)).thenReturn(Optional.of(scan));
        // Precise attribution: stub the new method, NOT findIdsByFirstSeenBetween
        when(deviceRepository.findIdsByLastSeenByScanId(7L))
            .thenReturn(List.of(101L, 102L));

        mockMvc.perform(get("/api/scans/7"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(7))
            .andExpect(jsonPath("$.cidr").value("10.0.0.0/24"))
            .andExpect(jsonPath("$.status").value("COMPLETE"))
            .andExpect(jsonPath("$.discoveredDeviceIds.length()").value(2))
            .andExpect(jsonPath("$.discoveredDeviceIds[0]").value(101))
            .andExpect(jsonPath("$.discoveredDeviceIds[1]").value(102));
    }

    @Test
    void getById_scanWithNoDiscoveredDevices_returnsEmptyList() throws Exception {
        Scan scan = new Scan();
        scan.setId(7L);
        scan.setCidr("10.0.0.0/24");
        scan.setScanType("PING_SWEEP");
        scan.setStatus(ScanStatus.COMPLETE);
        scan.setRequestedAt(Instant.parse("2024-01-01T00:00:00Z"));
        scan.setCompletedAt(Instant.parse("2024-01-01T00:05:00Z"));

        when(scanRepository.findById(7L)).thenReturn(Optional.of(scan));
        // Precise attribution: stub the new method returning empty
        when(deviceRepository.findIdsByLastSeenByScanId(7L))
            .thenReturn(List.of());

        mockMvc.perform(get("/api/scans/7"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.discoveredDeviceIds.length()").value(0));
    }

    @Test
    void getById_missingScan_returns404() throws Exception {
        when(scanRepository.findById(99999L)).thenReturn(Optional.empty());
        mockMvc.perform(get("/api/scans/99999"))
            .andExpect(status().isNotFound());
        verifyNoInteractions(deviceRepository);
    }
}
