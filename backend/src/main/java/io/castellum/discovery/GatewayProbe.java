package io.castellum.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Extracts the default-route gateway from {@code /proc/net/route} and emits it as a
 * single {@link DiscoveredNeighbor} so the router itself always lands in the inventory.
 *
 * <p>Same proc file (and property) as {@link ActiveNetworkDetector}, but a different
 * field: the detector derives the connected network from the on-link row, while this
 * probe reads the {@code Gateway} column of the default row ({@code Destination=00000000
 * && Mask=00000000}). The little-endian hex decode mirrors the detector's.
 *
 * <p>Returns an empty list when the proc file is absent (Windows/macOS, CI) or no
 * default route exists — never throws.
 */
@Service
public class GatewayProbe {

    private static final Logger log = LoggerFactory.getLogger(GatewayProbe.class);

    private static final String ALL_ZEROS_HEX = "00000000";

    private final String routePath;

    public GatewayProbe(@Value("${castellum.discovery.route.proc-path:/proc/net/route}") String routePath) {
        this.routePath = routePath;
    }

    /**
     * Returns the default gateway as a 0-or-1 element neighbor list (MAC null —
     * the ARP source supplies it when the gateway is also in the ARP cache).
     */
    public List<DiscoveredNeighbor> probe() {
        Path file = Path.of(routePath);
        if (!Files.exists(file)) {
            log.debug("Route table not found at {}; returning empty", routePath);
            return List.of();
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.debug("Failed to read route table {}: {}", routePath, e.getMessage());
            return List.of();
        }

        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            String[] fields = trimmed.split("\\s+");
            if (fields.length < 8) continue;
            // Skip header
            if ("Iface".equalsIgnoreCase(fields[0])) continue;

            String dest = fields[1].toUpperCase();
            String gw   = fields[2].toUpperCase();
            String mask = fields[7].toUpperCase();

            // Default route: Destination=0, Mask=0, Gateway≠0 (same predicate as
            // ActiveNetworkDetector.parseRouteTable's first pass).
            if (ALL_ZEROS_HEX.equals(dest) && ALL_ZEROS_HEX.equals(mask)
                    && !ALL_ZEROS_HEX.equals(gw)) {
                String gatewayIp = hexLeToIp(gw);
                if (gatewayIp == null) {
                    log.debug("Skipping default-route row with unparseable gateway '{}' in {}",
                        gw, routePath);
                    continue;
                }
                return List.of(new DiscoveredNeighbor(gatewayIp, null, null, null, fields[0], null));
            }
        }

        log.debug("No default route found in {}; returning empty", routePath);
        return List.of();
    }

    /**
     * Converts a little-endian 8-hex-char field to a dotted-quad IPv4 string, or null
     * when the field is not exactly 8 hex chars — the route file is config-redirectable,
     * so a malformed row must be skipped, not thrown (the class contract is never-throws).
     */
    private static String hexLeToIp(String hexLe) {
        if (hexLe.length() != 8) {
            return null;
        }
        int be;
        try {
            be = Integer.reverseBytes((int) Long.parseLong(hexLe, 16));
        } catch (NumberFormatException e) {
            return null;
        }
        return ((be >>> 24) & 0xFF) + "."
             + ((be >>> 16) & 0xFF) + "."
             + ((be >>> 8)  & 0xFF) + "."
             + ( be         & 0xFF);
    }
}
