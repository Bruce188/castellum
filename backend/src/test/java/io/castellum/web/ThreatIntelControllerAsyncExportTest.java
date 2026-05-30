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
import io.castellum.threatintel.ExportQueueFullException;
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

    @Test
    void postExportAsync_queueFull_returns503() throws Exception {
        // ExportJobService.submit() throws ExportQueueFullException when the executor
        // rejects the task.  The controller (or GlobalExceptionHandler) must surface
        // this as HTTP 503 Service Unavailable — not a 500 internal error.
        //
        // RED: fails until GlobalExceptionHandler (or the controller) maps
        // ExportQueueFullException → 503.
        when(exportJobService.submit()).thenThrow(new ExportQueueFullException());

        mvc.perform(post("/api/threat-intel/export/async"))
                .andExpect(status().isServiceUnavailable());
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

    // ── trip3 review nit tests ────────────────────────────────────────────────

    // ── Test 1: VIEWER can GET (characterization, expected GREEN) ─────────────

    /**
     * VIEWER role must be allowed to GET the job status/stream endpoint.
     *
     * <p>The {@code @PreAuthorize("hasAnyRole('ADMIN','VIEWER')")} annotation already
     * includes VIEWER. This test characterises that — locks it against future
     * annotation regressions.
     *
     * <p><b>Characterization</b> — expected GREEN (annotation already present).
     */
    @Test
    @WithMockUser(roles = "VIEWER")
    void getExportAsync_viewerRole_returns200() throws Exception {
        ExportJob pendingJob = new ExportJob(
            "job-viewer-1",
            ExportJob.Status.PENDING,
            0,
            null,
            null,
            null,
            java.time.Instant.now()
        );
        when(exportJobService.get("job-viewer-1")).thenReturn(Optional.of(pendingJob));

        mvc.perform(get("/api/threat-intel/export/async/job-viewer-1"))
            .andExpect(status().isOk());
    }

    // ── Test 2: Unauthenticated GET → 401 (characterization, expected GREEN) ──

    /**
     * An unauthenticated request (no credentials) to the GET endpoint must
     * be rejected with 401 Unauthorized.
     *
     * <p>The security-config catch-all already returns 401 on unauthenticated access.
     * This test characterises that behaviour.
     *
     * <p><b>Characterization</b> — expected GREEN (security config already handles it).
     */
    @Test
    @org.springframework.security.test.context.support.WithAnonymousUser
    void getExportAsync_unauthenticated_returns401() throws Exception {
        mvc.perform(get("/api/threat-intel/export/async/any-job-id"))
            .andExpect(status().isUnauthorized());
    }

    // ── Test 3: Content-Length header on DONE stream (GENUINE RED) ───────────

    /**
     * When a DONE job is fetched, the response must include a {@code Content-Length}
     * header equal to the bundle file size in bytes.
     *
     * <p>Currently the controller calls:
     * <pre>
     *   return ResponseEntity.ok()
     *       .contentType(MediaType.APPLICATION_JSON)
     *       .body(stream);
     * </pre>
     * It never calls {@code .contentLength(n)}, so no {@code Content-Length} header
     * is emitted. Browsers and HTTP clients use {@code Content-Length} to show
     * accurate progress — its absence is a usability gap.
     *
     * <p><b>GENUINE RED</b> — implementer must add
     * {@code .contentLength(Files.size(file))} (or equivalent) to the controller's
     * DONE branch.
     */
    @Test
    void getExportAsync_doneJob_setsContentLengthHeader() throws Exception {
        String bundleJson = "{\"type\":\"bundle\",\"objects\":[]}";
        Path bundleFile = tempDir.resolve("bundle-cl-test.json");
        Files.writeString(bundleFile, bundleJson);
        long expectedLength = Files.size(bundleFile);

        ExportJob doneJob = new ExportJob(
            "job-cl-done",
            ExportJob.Status.DONE,
            1,
            "bundle--cl-test",
            bundleFile.toString(),
            null,
            java.time.Instant.now()
        );
        when(exportJobService.get("job-cl-done")).thenReturn(Optional.of(doneJob));

        MvcResult started = mvc.perform(
                get("/api/threat-intel/export/async/job-cl-done"))
            .andExpect(request().asyncStarted())
            .andReturn();

        MvcResult result = mvc.perform(asyncDispatch(started))
            .andExpect(status().isOk())
            .andReturn();

        String contentLength = result.getResponse().getHeader("Content-Length");
        assertThat(contentLength)
            .as("DONE-job stream response must include Content-Length = file size in bytes; "
                + "implementer must add .contentLength(Files.size(file)) to the DONE branch")
            .isNotNull();
        assertThat(Long.parseLong(contentLength))
            .as("Content-Length must equal the actual byte length of the bundle file")
            .isEqualTo(expectedLength);
    }

    // ── Test 4: Temp file removed after stream — deferred ────────────────────
    //
    // Observing temp-file deletion in a @WebMvcTest slice is not cleanly possible:
    // ExportJobService is mocked, so the temp file's lifecycle (delete-after-stream)
    // lives entirely inside the production ExportJobService and cannot be verified
    // through the controller mock without coupling the test to internal plumbing.
    //
    // This is deferred to implementer verification:
    //   - Implementer should add a test at the ExportJobService level that, after
    //     runExport() writes the file and the DONE job is consumed (e.g. via a
    //     deleteAfterStream(jobId) method), the file no longer exists on disk.
    //   - Or: an integration test that wires a real (inline-executor) ExportJobService
    //     against a TestRestTemplate and asserts Files.exists(path) returns false after
    //     the GET stream completes.

    // ── Test 5: Status JSON escapes control chars — tab + null (GENUINE RED) ──

    /**
     * A FAILED job whose {@code error} message contains a tab ({@code \t}) or
     * null byte ({@code  }) must return a response body that is valid JSON.
     *
     * <p>The current {@code jsonEscape} helper handles only {@code \\}, {@code \"},
     * {@code \n}, and {@code \r}. It does NOT escape {@code \t} or the low control
     * characters {@code U+0000–U+001F}, which are prohibited unescaped inside JSON
     * strings (RFC 7159 §7). An error string containing any of these characters
     * produces invalid JSON that cannot be parsed.
     *
     * <p><b>GENUINE RED</b> — implementer must extend {@code jsonEscape} to cover
     * {@code \t} and the full {@code U+0000–U+001F} range, OR replace the
     * hand-rolled builder with {@code ObjectMapper.writeValueAsString(job)}.
     */
    @Test
    void getExportAsync_failedJob_errorWithTabAndNullByte_isValidJson() throws Exception {
        // Error message containing a tab and a null byte — both forbidden unescaped in JSON
        String errorWithControlChars = "upstream\terror details";

        ExportJob failedJob = new ExportJob(
            "job-ctrl-failed",
            ExportJob.Status.FAILED,
            0,
            null,
            null,
            errorWithControlChars,
            java.time.Instant.now()
        );
        when(exportJobService.get("job-ctrl-failed")).thenReturn(Optional.of(failedJob));

        mvc.perform(get("/api/threat-intel/export/async/job-ctrl-failed"))
            .andExpect(status().isOk())
            .andExpect(result -> {
                String body = result.getResponse().getContentAsString();
                // Body must be parseable as JSON — if jsonEscape is incomplete,
                // Jackson's ObjectMapper will throw JsonParseException here.
                com.fasterxml.jackson.databind.ObjectMapper om =
                    new com.fasterxml.jackson.databind.ObjectMapper();
                com.fasterxml.jackson.databind.JsonNode node = om.readTree(body);
                assertThat(node.get("status").asText()).isEqualTo("FAILED");
                // The error field must be present and contain no raw control characters
                assertThat(node.has("error"))
                    .as("error field must be present in FAILED job status JSON")
                    .isTrue();
            });
    }
}
