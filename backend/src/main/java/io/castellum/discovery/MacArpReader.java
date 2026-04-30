package io.castellum.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * macOS {@link ArpReader} that shells out to {@code arp -an} and parses output of the form:
 * <pre>? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]</pre>
 *
 * <p>Skips lines containing {@code (incomplete)} — entries the kernel knows about by IP but
 * has not yet ARP-resolved.
 *
 * <p>Single-hex-digit MAC octets emitted by some BSD-derived stacks (e.g. {@code 0:1:2:3:4:5})
 * are zero-padded to two digits via {@link #padMac(String)}.
 */
@Service
public class MacArpReader implements ArpReader {

    private static final Logger log = LoggerFactory.getLogger(MacArpReader.class);

    private static final Pattern ROW_RE = Pattern.compile(
        "^\\? \\((?<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)\\) at (?<mac>[0-9a-f:]+) on (?<iface>\\S+)",
        Pattern.CASE_INSENSITIVE);

    private final Function<List<String>, Process> processLauncher;

    public MacArpReader() {
        this(args -> {
            try {
                return new ProcessBuilder(args).redirectErrorStream(true).start();
            } catch (IOException e) {
                throw new UncheckedProcessLaunchException(e);
            }
        });
    }

    /** Package-private testing seam — inject a stub launcher. */
    MacArpReader(Function<List<String>, Process> processLauncher) {
        this.processLauncher = processLauncher;
    }

    @Override
    public List<DiscoveredNeighbor> read() throws DiscoveryUnavailableException {
        Process p;
        try {
            p = processLauncher.apply(List.of("arp", "-an"));
        } catch (UncheckedProcessLaunchException e) {
            throw new DiscoveryUnavailableException("Failed to launch arp -an: " + e.getCause().getMessage(), e.getCause());
        } catch (RuntimeException e) {
            throw new DiscoveryUnavailableException("Failed to launch arp -an: " + e.getMessage(), e);
        }
        try {
            if (!p.waitFor(5, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                throw new DiscoveryUnavailableException("arp -an timed out after 5s");
            }
            String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return parse(stdout);
        } catch (IOException e) {
            throw new DiscoveryUnavailableException("Failed to read arp -an stdout: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new DiscoveryUnavailableException("Interrupted waiting for arp -an", e);
        }
    }

    /** Pure-function parser. Skips {@code (incomplete)} rows and lines that fail the regex. */
    static List<DiscoveredNeighbor> parse(String stdout) {
        List<DiscoveredNeighbor> out = new ArrayList<>();
        if (stdout == null || stdout.isBlank()) return out;
        for (String line : stdout.split("\\R")) {
            String trimmed = line.strip();
            if (trimmed.isEmpty()) continue;
            if (trimmed.contains("(incomplete)")) {
                log.debug("Skipping incomplete arp -an entry: {}", trimmed);
                continue;
            }
            Matcher m = ROW_RE.matcher(trimmed);
            if (!m.find()) {
                log.debug("Skipping unparseable arp -an line: {}", trimmed);
                continue;
            }
            String ip = m.group("ip");
            String mac = padMac(m.group("mac").toLowerCase());
            String iface = m.group("iface");
            out.add(new DiscoveredNeighbor(ip, mac, null, null, iface, null));
        }
        return out;
    }

    /** Zero-pads any single-hex-digit octets to two digits. {@code 0:1:b:23:4:f} → {@code 00:01:0b:23:04:0f}. */
    static String padMac(String raw) {
        return Arrays.stream(raw.split(":"))
            .map(o -> o.length() == 1 ? "0" + o : o)
            .collect(Collectors.joining(":"));
    }

    private static final class UncheckedProcessLaunchException extends RuntimeException {
        UncheckedProcessLaunchException(IOException cause) { super(cause); }
    }
}
