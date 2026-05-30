package io.castellum.threatintel;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ExportJobService}.
 *
 * <p>Async is driven synchronously: a same-thread {@link Executor} is injected so
 * {@code runExport} executes inline — no sleeps, no race conditions.
 */
@ExtendWith(MockitoExtension.class)
class ExportJobServiceTest {

    @Mock
    ThreatIntelService threatIntelService;

    /** Inline executor — runs the submitted Runnable on the calling thread immediately. */
    private static final Executor INLINE_EXECUTOR = Runnable::run;

    private ExportJobService service;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        service = new ExportJobService(threatIntelService, INLINE_EXECUTOR, tempDir);
    }

    // ── submit() contract ─────────────────────────────────────────────────────

    @Test
    void submit_returnsNonNullJobId() throws JsonProcessingException {
        stubExportBundle("bundle--test-1", 5, "{\"type\":\"bundle\"}");

        String jobId = service.submit();

        assertThat(jobId).isNotNull().isNotBlank();
    }

    @Test
    void submit_jobIsPresentAfterSubmit() throws JsonProcessingException {
        stubExportBundle("bundle--test-1", 5, "{\"type\":\"bundle\"}");

        String jobId = service.submit();

        assertThat(service.get(jobId)).isPresent();
    }

    // ── DONE path ─────────────────────────────────────────────────────────────

    @Test
    void runExport_setsStatusDone_whenExportSucceeds() throws JsonProcessingException {
        String bundleJson = "{\"type\":\"bundle\",\"objects\":[]}";
        stubExportBundle("bundle--done-1", 7, bundleJson);

        String jobId = service.submit(); // runExport runs inline

        ExportJob job = service.get(jobId).orElseThrow();
        assertThat(job.status()).isEqualTo(ExportJob.Status.DONE);
    }

    @Test
    void runExport_setsObjectCount_whenExportSucceeds() throws JsonProcessingException {
        stubExportBundle("bundle--done-2", 7, "{\"type\":\"bundle\"}");

        String jobId = service.submit();

        ExportJob job = service.get(jobId).orElseThrow();
        assertThat(job.objectCount()).isEqualTo(7);
    }

    @Test
    void runExport_setsBundleId_whenExportSucceeds() throws JsonProcessingException {
        stubExportBundle("bundle--done-3", 3, "{\"type\":\"bundle\"}");

        String jobId = service.submit();

        ExportJob job = service.get(jobId).orElseThrow();
        assertThat(job.bundleId()).isEqualTo("bundle--done-3");
    }

    @Test
    void runExport_writesJsonToTempFile_notHeldInHeap() throws JsonProcessingException, IOException {
        String bundleJson = "{\"type\":\"bundle\",\"id\":\"bundle--heap-check\"}";
        stubExportBundle("bundle--heap-check", 1, bundleJson);

        String jobId = service.submit();

        ExportJob job = service.get(jobId).orElseThrow();
        assertThat(job.filePath()).isNotNull();

        Path file = Path.of(job.filePath());
        assertThat(file).exists();
        String fileContents = Files.readString(file);
        assertThat(fileContents).isEqualTo(bundleJson);
    }

    @Test
    void runExport_fileContainsSerializedBundleJson() throws JsonProcessingException, IOException {
        String bundleJson = "{\"type\":\"bundle\",\"objects\":[{\"type\":\"identity\"}]}";
        stubExportBundle("bundle--serial-1", 1, bundleJson);

        String jobId = service.submit();

        ExportJob job = service.get(jobId).orElseThrow();
        String contents = Files.readString(Path.of(job.filePath()));
        assertThat(contents).contains("\"type\":\"bundle\"");
    }

    // ── FAILED path ───────────────────────────────────────────────────────────

    @Test
    void runExport_setsStatusFailed_whenExportThrows() throws JsonProcessingException {
        when(threatIntelService.exportBundle())
            .thenThrow(new RuntimeException("downstream failure"));

        String jobId = service.submit();

        ExportJob job = service.get(jobId).orElseThrow();
        assertThat(job.status()).isEqualTo(ExportJob.Status.FAILED);
    }

    @Test
    void runExport_setsErrorMessage_whenExportThrows() throws JsonProcessingException {
        when(threatIntelService.exportBundle())
            .thenThrow(new RuntimeException("downstream failure"));

        String jobId = service.submit();

        ExportJob job = service.get(jobId).orElseThrow();
        assertThat(job.error()).isNotNull().contains("downstream failure");
    }

    @Test
    void runExport_hasNoFilePath_whenExportThrows() throws JsonProcessingException {
        when(threatIntelService.exportBundle())
            .thenThrow(new RuntimeException("boom"));

        String jobId = service.submit();

        ExportJob job = service.get(jobId).orElseThrow();
        assertThat(job.filePath()).isNull();
    }

    // ── get() for unknown id ─────────────────────────────────────────────────

    @Test
    void get_unknownJobId_returnsEmpty() {
        Optional<ExportJob> result = service.get("does-not-exist-uuid");

        assertThat(result).isEmpty();
    }

    // ── submittedAt is recorded ───────────────────────────────────────────────

    @Test
    void job_hasSubmittedAt_setOnSubmit() throws JsonProcessingException {
        stubExportBundle("bundle--ts", 2, "{\"type\":\"bundle\"}");

        String jobId = service.submit();

        ExportJob job = service.get(jobId).orElseThrow();
        assertThat(job.submittedAt()).isNotNull();
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private void stubExportBundle(String bundleId, int objects, String json)
            throws JsonProcessingException {
        when(threatIntelService.exportBundle())
            .thenReturn(new ThreatIntelService.ExportResult(bundleId, objects, json));
    }
}
