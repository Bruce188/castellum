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
import io.castellum.web.dto.ScanReportDto;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * RED-phase tests for GET /api/scans/{id}/report.
 *
 * Verifies: 200 for ADMIN and VIEWER with correct JSON shape; 401 for anonymous;
 * 404 for a missing scan; and that the attributed device set carries delta + services + cveIds.
 */
@WebMvcTest(ScanController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class ScanReportControllerTest {

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

    // ── helper: a minimal but fully-populated ScanReportDto ─────────────────────

    private ScanReportDto sampleReport(Long scanId) {
        Instant requested = Instant.parse("2024-06-01T10:00:00Z");
        Instant completed = Instant.parse("2024-06-01T10:05:00Z");

        ScanReportDto.ScanSummary summary = new ScanReportDto.ScanSummary(
            scanId, "10.0.0.0/24", "PING_SWEEP", ScanStatus.COMPLETE,
            requested, completed, 300_000L, null, 0,
            /* deviceCount */ 1, /* serviceCount */ 1, /* cveCount */ 1
        );

        ScanReportDto.ServiceRowDto svc = new ScanReportDto.ServiceRowDto(1L, 22, "tcp", "openssh", "8.4");

        ScanReportDto.SnapshotDeviceDto device = new ScanReportDto.SnapshotDeviceDto(
            101L, "10.0.0.1", "host-1",
            "new",
            List.of(svc),
            List.of("CVE-2024-0001")
        );

        return new ScanReportDto(summary, List.of(device));
    }

    // ── (a) ADMIN gets 200 with correct JSON shape ───────────────────────────────

    @Test
    @WithMockUser(roles = "ADMIN")
    void report_adminAllowed_returns200WithSummaryAndDevices() throws Exception {
        when(scanReportService.buildReport(7L)).thenReturn(sampleReport(7L));

        mockMvc.perform(get("/api/scans/7/report"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.summary.scanId").value(7))
            .andExpect(jsonPath("$.summary.cidr").value("10.0.0.0/24"))
            .andExpect(jsonPath("$.summary.deviceCount").value(1))
            .andExpect(jsonPath("$.summary.serviceCount").value(1))
            .andExpect(jsonPath("$.summary.cveCount").value(1))
            .andExpect(jsonPath("$.devices[0].delta").value("new"))
            .andExpect(jsonPath("$.devices[0].ipAddress").value("10.0.0.1"))
            .andExpect(jsonPath("$.devices[0].services").isArray())
            .andExpect(jsonPath("$.devices[0].services[0].port").value(22))
            .andExpect(jsonPath("$.devices[0].cveIds").isArray())
            .andExpect(jsonPath("$.devices[0].cveIds[0]").value("CVE-2024-0001"));
    }

    // ── (b) VIEWER gets 200 (auth parity with /api/scans/{id}) ──────────────────

    @Test
    @WithMockUser(roles = "VIEWER")
    void report_viewerAllowed_returns200() throws Exception {
        when(scanReportService.buildReport(7L)).thenReturn(sampleReport(7L));

        mockMvc.perform(get("/api/scans/7/report"))
            .andExpect(status().isOk());
    }

    // ── (c) anonymous gets 401 ───────────────────────────────────────────────────

    @Test
    void report_anonymousUser_returns401() throws Exception {
        mockMvc.perform(get("/api/scans/7/report").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    // ── (d) missing scan returns 404 ────────────────────────────────────────────

    @Test
    void report_missingScan_returns404() throws Exception {
        when(scanReportService.buildReport(99999L))
            .thenThrow(new NoSuchElementException("scan not found"));

        mockMvc.perform(get("/api/scans/99999/report"))
            .andExpect(status().isNotFound());
    }

    // ── (e) delta field is one of the three legal values ────────────────────────

    @Test
    @WithMockUser(roles = "ADMIN")
    void report_deltaIsLegalValue() throws Exception {
        when(scanReportService.buildReport(7L)).thenReturn(sampleReport(7L));

        mockMvc.perform(get("/api/scans/7/report"))
            .andExpect(status().isOk())
            // delta must be one of new|changed|unchanged — we assert it is a string value
            .andExpect(jsonPath("$.devices[0].delta").value("new"));
    }

    // ── (f) durationMillis present in summary ───────────────────────────────────

    @Test
    @WithMockUser(roles = "ADMIN")
    void report_summaryContainsDurationMillis() throws Exception {
        when(scanReportService.buildReport(7L)).thenReturn(sampleReport(7L));

        mockMvc.perform(get("/api/scans/7/report"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.summary.durationMillis").value(300_000L));
    }
}
