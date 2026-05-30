package io.castellum.threatintel;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

/**
 * Manages async STIX-bundle export jobs.
 *
 * <p>Jobs are kept in an in-memory {@link ConcurrentHashMap}. The bundle JSON is
 * written to a temp file on completion — it is NOT held as a heap String on the job
 * record. A {@link Path} hint for the temp-file parent may be injected (for testing);
 * production code passes {@code null} which lets {@link Files#createTempFile} use the
 * JVM default temp directory.
 *
 * <p>The executor is constructor-injected so unit tests can substitute a same-thread
 * executor and drive {@code runExport} deterministically without sleeps.
 */
@Service
public class ExportJobService {

    private final ThreatIntelService threatIntelService;
    private final Executor executor;
    private final Path tempDir;

    private final ConcurrentHashMap<String, ExportJob> jobs = new ConcurrentHashMap<>();

    /**
     * Primary Spring-managed constructor — executor resolved by qualifier.
     */
    @Autowired
    public ExportJobService(ThreatIntelService threatIntelService,
                            @Qualifier("exportTaskExecutor") Executor executor) {
        this(threatIntelService, executor, null);
    }

    /**
     * Testing constructor — allows injecting a temp-dir root and inline executor.
     */
    ExportJobService(ThreatIntelService threatIntelService, Executor executor, Path tempDir) {
        this.threatIntelService = threatIntelService;
        this.executor = executor;
        this.tempDir = tempDir;
    }

    /**
     * Submit a new export job.
     *
     * @return the job ID (UUID string)
     */
    public String submit() {
        String jobId = UUID.randomUUID().toString();
        ExportJob job = new ExportJob(
                jobId,
                ExportJob.Status.PENDING,
                0,
                null,
                null,
                null,
                Instant.now()
        );
        jobs.put(jobId, job);
        try {
            executor.execute(() -> runExport(jobId));
        } catch (RejectedExecutionException e) {
            jobs.remove(jobId);
            throw new ExportQueueFullException("Export queue is full — try again later", e);
        }
        return jobId;
    }

    /**
     * Execute the export for the given job ID.
     *
     * <p>Sets the job to RUNNING, calls {@link ThreatIntelService#exportBundle()},
     * writes JSON to a temp file, and updates the job to DONE. On any exception the
     * job is set to FAILED with the error message.
     */
    public void runExport(String jobId) {
        setRunning(jobId);
        try {
            ThreatIntelService.ExportResult result = threatIntelService.exportBundle();
            Path file = writeTempFile(result.json());
            ExportJob done = new ExportJob(
                    jobId,
                    ExportJob.Status.DONE,
                    result.objects(),
                    result.bundleId(),
                    file.toString(),
                    null,
                    jobs.get(jobId).submittedAt()
            );
            jobs.put(jobId, done);
        } catch (Exception e) {
            ExportJob failed = new ExportJob(
                    jobId,
                    ExportJob.Status.FAILED,
                    0,
                    null,
                    null,
                    e.getMessage(),
                    jobs.get(jobId).submittedAt()
            );
            jobs.put(jobId, failed);
        }
    }

    /**
     * Look up a job by ID.
     *
     * @return present if found, empty if unknown
     */
    public Optional<ExportJob> get(String id) {
        return Optional.ofNullable(jobs.get(id));
    }

    // ── private helpers ────────────────────────────────────────────────────────

    private void setRunning(String jobId) {
        ExportJob current = jobs.get(jobId);
        if (current == null) return;
        jobs.put(jobId, new ExportJob(
                jobId,
                ExportJob.Status.RUNNING,
                current.objectCount(),
                current.bundleId(),
                current.filePath(),
                current.error(),
                current.submittedAt()
        ));
    }

    private Path writeTempFile(String json) throws IOException {
        Path file;
        if (tempDir != null) {
            file = Files.createTempFile(tempDir, "stix-bundle-", ".json");
        } else {
            file = Files.createTempFile("stix-bundle-", ".json");
        }
        Files.writeString(file, json, StandardCharsets.UTF_8);
        return file;
    }
}
