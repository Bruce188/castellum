package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import io.castellum.threatintel.ExportJob;
import io.castellum.threatintel.ExportJobService;
import io.castellum.threatintel.ThreatIntelService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * {@code @WebMvcTest} slice for the async-export endpoints on {@link ThreatIntelController}.
 *
 * <ul>
 *   <li>{@code POST /api/threat-intel/export/async} → 202 + {@code {jobId, status}}
 *   <li>{@code GET  /api/threat-intel/export/async/{jobId}} when DONE → 200 streaming JSON
 *   <li>{@code GET  /api/threat-intel/export/async/{jobId}} when PENDING → 200 status JSON
 *   <li>{@code GET  /api/threat-intel/export/async/{jobId}} when unknown → 404
 * </ul>
 */
@WebMvcTest(ThreatIntelController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class,
        RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class ThreatIntelControllerAsyncExportTest {

    @Autowired
    MockMvc mvc;

    @MockBean
    AuditService auditService;

    @MockBean
    ThreatIntelService service;

    @MockBean
    ExportJobService exportJobService;

    @MockBean
    CastellumUserDetailsService castellumUserDetailsService;

    @MockBean
    JwtService jwtService;

    @MockBean
    UserRepository userRepository;

    @TempDir
    Path tempDir;

    // ── POST /export/async → 202 ──────────────────────────────────────────────

    @Test
    void postExportAsync_returns202_withJobIdAndStatus() throws Exception {
        when(exportJobService.submit()).thenReturn("job-uuid-001");

        mvc.perform(post("/api/threat-intel/export/async"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.jobId").value("job-uuid-001"))
            .andExpect(jsonPath("$.status").value("PENDING"));
    }

    @Test
    void postExportAsync_requires_adminRole() throws Exception {
        mvc.perform(post("/api/threat-intel/export/async"))
            .andExpect(status().isAccepted()); // admin mock user at class level
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void postExportAsync_viewer_returns403() throws Exception {
        mvc.perform(post("/api/threat-intel/export/async"))
            .andExpect(status().isForbidden());
    }

    // ── GET /export/async/{jobId} — DONE → stream file ───────────────────────

    @Test
    void getExportAsync_doneJob_streams_bundleJson() throws Exception {
        String bundleJson = "{\"type\":\"bundle\",\"objects\":[]}";
        Path bundleFile = tempDir.resolve("bundle-test.json");
        Files.writeString(bundleFile, bundleJson);

        ExportJob doneJob = new ExportJob(
            "job-uuid-done",
            ExportJob.Status.DONE,
            5,
            "bundle--abc",
            bundleFile.toString(),
            null,
            Instant.now()
        );
        when(exportJobService.get("job-uuid-done")).thenReturn(Optional.of(doneJob));

        MvcResult started = mvc.perform(
                get("/api/threat-intel/export/async/job-uuid-done"))
            .andExpect(request().asyncStarted())
            .andReturn();

        MvcResult result = mvc.perform(asyncDispatch(started))
            .andExpect(status().isOk())
            .andReturn();

        String body = result.getResponse().getContentAsString();
        assertThat(body).isEqualTo(bundleJson);

        String contentType = result.getResponse().getContentType();
        assertThat(contentType).startsWith("application/json");
    }

    // ── GET /export/async/{jobId} — PENDING → status JSON ────────────────────

    @Test
    void getExportAsync_pendingJob_returnsStatusJson() throws Exception {
        ExportJob pendingJob = new ExportJob(
            "job-uuid-pending",
            ExportJob.Status.PENDING,
            0,
            null,
            null,
            null,
            Instant.now()
        );
        when(exportJobService.get("job-uuid-pending")).thenReturn(Optional.of(pendingJob));

        mvc.perform(get("/api/threat-intel/export/async/job-uuid-pending"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value("job-uuid-pending"))
            .andExpect(jsonPath("$.status").value("PENDING"));
    }

    // ── GET /export/async/{jobId} — RUNNING → status JSON ────────────────────

    @Test
    void getExportAsync_runningJob_returnsStatusJson() throws Exception {
        ExportJob runningJob = new ExportJob(
            "job-uuid-running",
            ExportJob.Status.RUNNING,
            0,
            null,
            null,
            null,
            Instant.now()
        );
        when(exportJobService.get("job-uuid-running")).thenReturn(Optional.of(runningJob));

        mvc.perform(get("/api/threat-intel/export/async/job-uuid-running"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("RUNNING"));
    }

    // ── GET /export/async/{jobId} — FAILED → status JSON with error ──────────

    @Test
    void getExportAsync_failedJob_returnsStatusJsonWithError() throws Exception {
        ExportJob failedJob = new ExportJob(
            "job-uuid-failed",
            ExportJob.Status.FAILED,
            0,
            null,
            null,
            "downstream failure",
            Instant.now()
        );
        when(exportJobService.get("job-uuid-failed")).thenReturn(Optional.of(failedJob));

        mvc.perform(get("/api/threat-intel/export/async/job-uuid-failed"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("FAILED"))
            .andExpect(jsonPath("$.error").value("downstream failure"));
    }

    // ── GET /export/async/{jobId} — unknown → 404 ────────────────────────────

    @Test
    void getExportAsync_unknownJobId_returns404() throws Exception {
        when(exportJobService.get(anyString())).thenReturn(Optional.empty());

        mvc.perform(get("/api/threat-intel/export/async/no-such-job"))
            .andExpect(status().isNotFound());
    }
}
