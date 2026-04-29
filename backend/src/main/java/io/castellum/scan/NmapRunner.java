package io.castellum.scan;

import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

@Service
public class NmapRunner {

    /** Maximum bytes read from a single stream to prevent memory exhaustion. */
    private static final int MAX_OUTPUT_BYTES = 10 * 1024 * 1024; // 10 MB

    /** Package-private: overrides executor factory for testing only. */
    interface ExecutorFactory {
        ExecutorService create();
    }

    private final ExecutorFactory executorFactory;

    public NmapRunner() {
        this.executorFactory = () -> Executors.newFixedThreadPool(2);
    }

    /** Package-private constructor for testing with a spy executor factory. */
    NmapRunner(ExecutorFactory executorFactory) {
        this.executorFactory = executorFactory;
    }

    public NmapResult run(String cidr, ScanType type) throws InterruptedException, IOException {
        String validatedCidr = CidrValidator.requireValid(cidr);

        List<String> argv = new ArrayList<>();
        argv.add("nmap");
        argv.addAll(type.argv());
        argv.add(validatedCidr);

        ProcessBuilder pb = new ProcessBuilder(argv);
        pb.redirectErrorStream(false);
        Process process = pb.start();

        // Drain stdout and stderr concurrently to prevent OS pipe-buffer deadlock.
        ExecutorService drainer = executorFactory.create();
        try {
            Future<byte[]> stdoutFuture = drainer.submit(() -> readCapped(process.getInputStream(), MAX_OUTPUT_BYTES));
            Future<byte[]> stderrFuture = drainer.submit(() -> readCapped(process.getErrorStream(), MAX_OUTPUT_BYTES));
            drainer.shutdown();

            boolean finished = process.waitFor(60, TimeUnit.SECONDS);
            if (!finished) {
                throw new IOException("nmap timed out");
            }

            try {
                byte[] stdout = stdoutFuture.get();
                byte[] stderr = stderrFuture.get();
                return new NmapResult(process.exitValue(),
                    new String(stdout, java.nio.charset.StandardCharsets.UTF_8),
                    new String(stderr, java.nio.charset.StandardCharsets.UTF_8));
            } catch (ExecutionException e) {
                throw new IOException("failed to read nmap output", e.getCause());
            }
        } finally {
            // Forcibly destroy the process on all exit paths (timeout, error, interruption).
            // This closes the process's stdout/stderr pipes, allowing drainer threads to unblock.
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
                if (total >= maxBytes) break;
            }
            return buf.toByteArray();
        }
    }
}
