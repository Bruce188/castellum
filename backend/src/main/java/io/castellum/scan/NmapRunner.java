package io.castellum.scan;

import org.springframework.beans.factory.annotation.Autowired;
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
    private final NmapScanProperties props;

    /** Single private delegate constructor — all public constructors delegate here. */
    private NmapRunner(ExecutorFactory executorFactory, NmapScanProperties props) {
        this.executorFactory = executorFactory;
        this.props = props;
    }

    public NmapRunner() {
        this(() -> Executors.newFixedThreadPool(2), new NmapScanProperties());
    }

    /** Package-private constructor for testing with a spy executor factory. */
    NmapRunner(ExecutorFactory executorFactory) {
        this(executorFactory, new NmapScanProperties());
    }

    /** Spring-used constructor — injects configurable scan properties. */
    @Autowired
    public NmapRunner(NmapScanProperties props) {
        this(() -> Executors.newFixedThreadPool(2), props);
    }

    /**
     * Pure argv assembly — package-private for unit testing without spawning nmap.
     * Takes an already-validated cidr. The whole-CIDR path always passes {@code -Pn} for
     * port-enumerating types (no prior host-discovery has happened).
     */
    List<String> buildArgv(String validatedCidr, ScanType type) {
        // Whole-CIDR scan: targets are unverified, so port-enumerating types keep -Pn.
        return buildArgv(List.of(validatedCidr), type, /* targetsKnownUp= */ false);
    }

    /**
     * Argv assembly for an explicit list of already-validated targets (single CIDR or a
     * list of host addresses). Package-private for unit testing.
     *
     * @param validatedTargets one or more validated targets (CIDR or host IPs); appended last
     * @param type             the scan type
     * @param targetsKnownUp   when {@code true}, the targets are confirmed alive (e.g. from a
     *                         prior PING_SWEEP) so {@code -Pn} is dropped even for
     *                         port-enumerating types — there is no benefit to forcing
     *                         host-discovery off and it avoids re-probing dead addresses.
     */
    List<String> buildArgv(List<String> validatedTargets, ScanType type, boolean targetsKnownUp) {
        List<String> argv = new ArrayList<>();
        argv.add("nmap");
        // Emit machine-readable XML to stdout for all scan types. The parser consumes this
        // XML to extract products and CPEs (text output lacks both). "-" = stdout.
        argv.add("-oX");
        argv.add("-");
        // Aggressive timing template; per-host timeout is scan-type-aware.
        argv.add("-T4");
        // Port-enumerating scan types (SERVICE_DETECT, OS_FINGERPRINT) use -Pn so hosts
        // that don't respond to host-discovery probes are still port-scanned.
        // PING_SWEEP omits -Pn — it relies on ICMP echo, not port scanning.
        // When the targets are already known-up (alive-host list from a completed PING_SWEEP),
        // -Pn is unnecessary and is dropped: every target is a real host, so the phantom
        // inflation that -Pn causes across a raw CIDR cannot occur.
        if (type.enumeratesPorts() && !targetsKnownUp) {
            argv.add("-Pn");
        }
        // Per-host timeout: longer budget for -sV (version detection needs more time),
        // shorter for -sn (ping sweep — just ICMP echo, no port scan).
        argv.add("--host-timeout");
        argv.add(type.enumeratesPorts() ? props.getPortScanHostTimeout() : props.getPingHostTimeout());
        argv.addAll(type.argv());
        argv.addAll(validatedTargets);
        return argv;
    }

    public NmapResult run(String cidr, ScanType type) throws InterruptedException, IOException {
        String validatedCidr = CidrValidator.requireValid(cidr);

        List<String> argv = buildArgv(validatedCidr, type);
        return execute(argv);
    }

    /**
     * Run nmap against an explicit list of already-up host addresses (alive-host path).
     * Used for SERVICE_DETECT after a PING_SWEEP has resolved the live set, so version
     * detection runs only against real hosts instead of every address in the CIDR.
     *
     * <p>Each host is validated as a single IPv4 address. {@code -Pn} is dropped because the
     * targets are confirmed alive. The caller must not pass an empty list — an empty alive
     * set is short-circuited upstream rather than handed to nmap (which would otherwise read
     * targets from stdin and hang).
     *
     * @param hosts non-empty list of validated host IP strings
     * @param type  the scan type
     */
    public NmapResult run(List<String> hosts, ScanType type) throws InterruptedException, IOException {
        if (hosts == null || hosts.isEmpty()) {
            throw new IllegalArgumentException("host list must not be empty");
        }
        List<String> validatedHosts = new ArrayList<>(hosts.size());
        for (String host : hosts) {
            validatedHosts.add(CidrValidator.requireValidHost(host));
        }
        List<String> argv = buildArgv(validatedHosts, type, /* targetsKnownUp= */ true);
        return execute(argv);
    }

    private NmapResult execute(List<String> argv) throws InterruptedException, IOException {

        ProcessBuilder pb = new ProcessBuilder(argv);
        pb.redirectErrorStream(false);
        Process process = pb.start();

        // Drain stdout and stderr concurrently to prevent OS pipe-buffer deadlock.
        ExecutorService drainer = executorFactory.create();
        try {
            Future<byte[]> stdoutFuture = drainer.submit(() -> readCapped(process.getInputStream(), MAX_OUTPUT_BYTES));
            Future<byte[]> stderrFuture = drainer.submit(() -> readCapped(process.getErrorStream(), MAX_OUTPUT_BYTES));
            drainer.shutdown();

            // Outer wall-clock cap (configurable via castellum.scan.nmap.process-timeout-seconds,
            // default 300s). With the per-type --host-timeout on the nmap side (30s for sweeps,
            // 180s for port-enumerating scans), a /24 of mostly dead hosts caps near
            // ceil(256/parallel_probes) × host-timeout; -T4 keeps responsive hosts fast. Larger
            // ranges (up to /22) can be accommodated by raising the property.
            boolean finished = process.waitFor(props.getProcessTimeoutSeconds(), TimeUnit.SECONDS);
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
