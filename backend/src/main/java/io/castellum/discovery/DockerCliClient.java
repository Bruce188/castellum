package io.castellum.discovery;

import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Thin wrapper around the local {@code docker} CLI, mirroring the {@code ProcessBuilder}
 * pattern in {@link io.castellum.scan.NmapRunner} (concurrent stdout/stderr drain to avoid
 * pipe-buffer deadlock, capped output, forced process teardown on every exit path).
 *
 * <p>The backend uid is a member of the {@code docker} group, so the daemon socket is
 * reachable without sudo. Two calls are exposed:
 * <ul>
 *   <li>{@link #listRunningContainerIds()} → {@code docker ps -q --no-trunc}</li>
 *   <li>{@link #inspect(List)} → {@code docker inspect <id…>} (JSON array on stdout)</li>
 * </ul>
 *
 * <p>The command runner is injected as a {@link CommandRunner} so unit tests can stub the CLI
 * output without spawning a real process.
 */
@Component
public class DockerCliClient {

    /** Cap a single stream read to bound memory on a pathological inspect dump. */
    private static final int MAX_OUTPUT_BYTES = 16 * 1024 * 1024; // 16 MB
    /** Outer wall-clock cap per docker invocation. */
    private static final int PROCESS_TIMEOUT_SECONDS = 30;

    /** Result of a CLI invocation. */
    public record CommandResult(int exitCode, String stdout, String stderr) {}

    /** Seam for tests: run an argv and return its captured result. */
    public interface CommandRunner {
        CommandResult run(List<String> argv) throws IOException, InterruptedException;
    }

    private final CommandRunner runner;

    public DockerCliClient() {
        this(DockerCliClient::runProcess);
    }

    /** Test/seam constructor. */
    public DockerCliClient(CommandRunner runner) {
        this.runner = runner;
    }

    /**
     * Returns the full (non-truncated) IDs of running containers.
     *
     * @throws DiscoveryUnavailableException if docker is absent, the daemon is unreachable,
     *                                       or the command fails / times out
     */
    public List<String> listRunningContainerIds() throws DiscoveryUnavailableException {
        CommandResult res = invoke(List.of("docker", "ps", "-q", "--no-trunc"));
        List<String> ids = new ArrayList<>();
        for (String line : res.stdout().split("\\R")) {
            String id = line.trim();
            if (!id.isEmpty()) {
                ids.add(id);
            }
        }
        return ids;
    }

    /**
     * Returns the raw {@code docker inspect} JSON array for the given container IDs.
     * Returns the empty-array literal {@code "[]"} when {@code ids} is empty (no spawn).
     *
     * @throws DiscoveryUnavailableException on command failure / timeout
     */
    public String inspect(List<String> ids) throws DiscoveryUnavailableException {
        if (ids == null || ids.isEmpty()) {
            return "[]";
        }
        List<String> argv = new ArrayList<>(ids.size() + 3);
        argv.add("docker");
        argv.add("inspect");
        argv.add("--"); // end-of-options guard: an id can never be parsed as a flag (defense-in-depth)
        argv.addAll(ids);
        return invoke(argv).stdout();
    }

    private CommandResult invoke(List<String> argv) throws DiscoveryUnavailableException {
        CommandResult res;
        try {
            res = runner.run(argv);
        } catch (IOException e) {
            // Most commonly: 'docker' not on PATH, or daemon socket not reachable.
            throw new DiscoveryUnavailableException(
                "docker CLI unavailable: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new DiscoveryUnavailableException("docker CLI interrupted", e);
        }
        if (res.exitCode() != 0) {
            String stderr = res.stderr() == null ? "" : res.stderr().trim();
            throw new DiscoveryUnavailableException(
                "docker command failed (exit " + res.exitCode() + "): " + stderr);
        }
        return res;
    }

    /**
     * Default {@link CommandRunner} — spawns the process, drains both streams concurrently on a
     * 2-thread pool, enforces a wall-clock timeout, and forcibly destroys the process on every
     * exit path. Verbatim-structured after {@link io.castellum.scan.NmapRunner#run}.
     */
    private static CommandResult runProcess(List<String> argv) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(argv);
        pb.redirectErrorStream(false);
        Process process = pb.start();

        ExecutorService drainer = Executors.newFixedThreadPool(2);
        try {
            Future<byte[]> stdoutFuture =
                drainer.submit(() -> readCapped(process.getInputStream(), MAX_OUTPUT_BYTES));
            Future<byte[]> stderrFuture =
                drainer.submit(() -> readCapped(process.getErrorStream(), MAX_OUTPUT_BYTES));
            drainer.shutdown();

            boolean finished = process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                throw new IOException("docker command timed out after " + PROCESS_TIMEOUT_SECONDS + "s");
            }
            try {
                byte[] stdout = stdoutFuture.get();
                byte[] stderr = stderrFuture.get();
                return new CommandResult(
                    process.exitValue(),
                    new String(stdout, StandardCharsets.UTF_8),
                    new String(stderr, StandardCharsets.UTF_8));
            } catch (ExecutionException e) {
                throw new IOException("failed to read docker output", e.getCause());
            }
        } finally {
            process.destroyForcibly();
            drainer.shutdownNow();
        }
    }

    private static byte[] readCapped(InputStream in, int maxBytes) throws IOException {
        try (in) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int read;
            int total = 0;
            while ((read = in.read(chunk)) != -1) {
                int allowed = Math.min(read, maxBytes - total);
                if (allowed > 0) {
                    buf.write(chunk, 0, allowed);
                    total += allowed;
                }
                if (total >= maxBytes) {
                    break;
                }
            }
            return buf.toByteArray();
        }
    }
}
