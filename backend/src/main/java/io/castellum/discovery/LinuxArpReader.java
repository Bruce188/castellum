package io.castellum.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Linux-specific {@link ArpReader} that parses {@code /proc/net/arp}. The path is
 * injectable for tests. Returns an empty list when the file does not exist (e.g. when
 * running on Windows/macOS or in a kernel-namespace-isolated container without ARP entries).
 *
 * <p>Pure file read — no shell-out, no privileges required.
 */
@Service
public class LinuxArpReader implements ArpReader {

    private static final Logger log = LoggerFactory.getLogger(LinuxArpReader.class);

    private static final Pattern IP_PATTERN    = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern MAC_PATTERN   = Pattern.compile("^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$");
    private static final Pattern HW_PATTERN    = Pattern.compile("^0x[0-9A-Fa-f]+$");
    private static final Pattern FLAGS_PATTERN = Pattern.compile("^0x[0-9A-Fa-f]+$");
    private static final Pattern IFACE_PATTERN = Pattern.compile("^[a-zA-Z0-9_:.\\-]{1,16}$");

    private static final String ZERO_MAC = "00:00:00:00:00:00";

    private final String procPath;

    public LinuxArpReader(@Value("${castellum.discovery.arp.proc-path:/proc/net/arp}") String procPath) {
        this.procPath = procPath;
    }

    @Override
    public List<DiscoveredNeighbor> read() {
        Path arpFile = Path.of(procPath);
        if (!Files.exists(arpFile)) {
            log.debug("ARP cache file not found at {}; returning empty list", procPath);
            return List.of();
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(arpFile, StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.warn("Failed to read ARP cache file {}: {}", procPath, e.getMessage());
            return List.of();
        }

        boolean headerSkipped = false;
        List<DiscoveredNeighbor> results = new ArrayList<>();

        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            if (!headerSkipped) {
                headerSkipped = true;
                continue;
            }
            parseLine(trimmed, results);
        }
        return results;
    }

    private void parseLine(String line, List<DiscoveredNeighbor> results) {
        String[] fields = line.split("\\s+");
        if (fields.length < 6) {
            log.debug("Skipping malformed ARP line (expected 6+ fields): {}", line);
            return;
        }

        String ip     = fields[0];
        String hwType = fields[1];
        String flags  = fields[2];
        String mac    = fields[3];
        String iface  = fields[5];

        if (!IP_PATTERN.matcher(ip).matches()) {
            log.debug("Skipping ARP line: invalid IP '{}'", ip);
            return;
        }
        if (!HW_PATTERN.matcher(hwType).matches()) {
            log.debug("Skipping ARP line: invalid HW type '{}'", hwType);
            return;
        }
        if (!FLAGS_PATTERN.matcher(flags).matches()) {
            log.debug("Skipping ARP line: invalid flags '{}'", flags);
            return;
        }
        if (!MAC_PATTERN.matcher(mac).matches()) {
            log.debug("Skipping ARP line: invalid MAC '{}'", mac);
            return;
        }
        if (ZERO_MAC.equalsIgnoreCase(mac)) {
            log.debug("Skipping incomplete ARP entry (zero MAC) for IP '{}'", ip);
            return;
        }
        if (!IFACE_PATTERN.matcher(iface).matches()) {
            log.debug("Skipping ARP line: invalid iface '{}'", iface);
            return;
        }

        results.add(new DiscoveredNeighbor(ip, mac, hwType, flags, iface, null));
    }
}
