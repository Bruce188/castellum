package io.castellum.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Windows {@link ArpReader} that shells out to {@code arp -a} and parses the
 * "Internet Address / Physical Address / Type" table.
 *
 * <p><strong>English-locale assumption:</strong> the parser keys on the dotted-quad / hex-MAC /
 * "dynamic|static" pattern. Non-English Windows distributions translate the column headers
 * but typically preserve the row layout — however this is not guaranteed. {@link #parse(String)}
 * silently drops any line that does not match and returns an empty list when the table is empty
 * or fully untranslatable.
 *
 * <p>Iface attribution is left {@code null}: Windows {@code arp -a} groups rows under
 * "Interface: 192.168.x.x" headers whose key word is locale-dependent, so we omit the iface field
 * rather than mis-attribute it. Callers that need iface attribution on Windows should use the
 * IP-Helper API (out of scope here).
 */
@Service
public class WindowsArpReader implements ArpReader {

    private static final Logger log = LoggerFactory.getLogger(WindowsArpReader.class);

    /**
     * Captures rows of the form:
     * <pre>  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic</pre>
     * Use {@link Pattern#CASE_INSENSITIVE} for the {@code dynamic|static} type field; the regex
     * itself uses lowercase {@code [0-9a-f]} for the MAC octets — the case-insensitive flag covers
     * uppercase variants on some Windows builds.
     */
    private static final Pattern ROW_RE = Pattern.compile(
        "^\\s*(?<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+(?<mac>[0-9a-f]{2}(-[0-9a-f]{2}){5})\\s+(?<type>dynamic|static)",
        Pattern.CASE_INSENSITIVE);

    private final Function<List<String>, Process> processLauncher;

    public WindowsArpReader() {
        this(args -> {
            try {
                return new ProcessBuilder(args).redirectErrorStream(true).start();
            } catch (IOException e) {
                throw new UncheckedProcessLaunchException(e);
            }
        });
    }

    /** Package-private testing seam — inject a stub launcher. */
    WindowsArpReader(Function<List<String>, Process> processLauncher) {
        this.processLauncher = processLauncher;
    }

    @Override
    public List<DiscoveredNeighbor> read() throws DiscoveryUnavailableException {
        Process p;
        try {
            p = processLauncher.apply(List.of("arp", "-a"));
        } catch (UncheckedProcessLaunchException e) {
            throw new DiscoveryUnavailableException("Failed to launch arp -a: " + e.getCause().getMessage(), e.getCause());
        } catch (RuntimeException e) {
            throw new DiscoveryUnavailableException("Failed to launch arp -a: " + e.getMessage(), e);
        }
        try {
            if (!p.waitFor(5, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                throw new DiscoveryUnavailableException("arp -a timed out after 5s");
            }
            String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return parse(stdout);
        } catch (IOException e) {
            throw new DiscoveryUnavailableException("Failed to read arp -a stdout: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new DiscoveryUnavailableException("Interrupted waiting for arp -a", e);
        }
    }

    /**
     * Pure-function parser over the captured stdout. Returns one {@link DiscoveredNeighbor}
     * per matching row. Unparseable lines are logged at DEBUG and skipped.
     */
    static List<DiscoveredNeighbor> parse(String stdout) {
        List<DiscoveredNeighbor> out = new ArrayList<>();
        if (stdout == null || stdout.isBlank()) return out;
        for (String line : stdout.split("\\R")) {
            String trimmed = line.strip();
            if (trimmed.isEmpty()) continue;
            Matcher m = ROW_RE.matcher(line);
            if (!m.find()) {
                log.debug("Skipping unparseable arp -a line: {}", trimmed);
                continue;
            }
            String ip = m.group("ip");
            String mac = m.group("mac").toLowerCase().replace('-', ':');
            String type = m.group("type").toLowerCase();
            out.add(new DiscoveredNeighbor(ip, mac, type, null, null, null));
        }
        return out;
    }

    /** Wraps {@link IOException} so the lambda in the default ctor can propagate it. */
    private static final class UncheckedProcessLaunchException extends RuntimeException {
        UncheckedProcessLaunchException(IOException cause) { super(cause); }
    }
}
