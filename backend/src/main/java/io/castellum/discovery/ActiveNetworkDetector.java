package io.castellum.discovery;

import io.castellum.scan.ScanSizeGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.Inet4Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Detects the host's primary-interface CIDR by parsing {@code /proc/net/route}.
 *
 * <p>The primary interface is the one carrying the default route
 * ({@code Destination=00000000 && Mask=00000000}). The connected network is
 * derived from the same-interface on-link row ({@code Gateway=00000000},
 * non-zero, non-host {@code Mask}).
 *
 * <p>The proc-path is injectable for testing (mirror of {@link LinuxArpReader}).
 * The IP resolver is a stubbable seam — tests inject a pure {@link Function}
 * instead of relying on real {@link NetworkInterface} enumeration.
 *
 * <p>Returns {@link Optional#empty()} when the proc file is absent, unreadable,
 * or contains no default route (e.g. on Windows/macOS or in CI).
 *
 * <p>If the detected prefix is wider than {@link ScanSizeGuard#MAX_ALLOWED_PREFIX},
 * the prefix is clamped to the cap, the network is recomputed using the host IP,
 * and a {@code note} is set.
 */
@Service
public class ActiveNetworkDetector {

    private static final Logger log = LoggerFactory.getLogger(ActiveNetworkDetector.class);

    private static final String ALL_ZEROS_HEX = "00000000";
    private static final String ALL_ONES_HEX  = "FFFFFFFF";

    private final String routePath;
    private final Function<String, Optional<Inet4Address>> ipResolver;

    /**
     * Production constructor — Spring-managed, uses real NetworkInterface.
     */
    public ActiveNetworkDetector(
            @Value("${castellum.discovery.route.proc-path:/proc/net/route}") String routePath) {
        this.routePath = routePath;
        this.ipResolver = ActiveNetworkDetector::resolveIp;
    }

    /**
     * Test-only constructor — injectable proc-path + stubbable IP resolver.
     * Mirrors {@code ArpCacheReader(String procPath)}.
     */
    public ActiveNetworkDetector(String routePath, Function<String, Optional<Inet4Address>> ipResolver) {
        this.routePath = routePath;
        this.ipResolver = ipResolver;
    }

    /**
     * Detects the active network CIDR. Returns empty on CI/non-Linux hosts or
     * when no default route is found.
     */
    public Optional<ActiveNetwork> detect() {
        Path file = Path.of(routePath);
        if (!Files.exists(file)) {
            log.debug("Route table not found at {}; returning empty", routePath);
            return Optional.empty();
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.warn("Failed to read route table {}: {}", routePath, e.getMessage());
            return Optional.empty();
        }

        Optional<ActiveNetwork> parsed = parseRouteTable(lines);
        if (parsed.isEmpty()) {
            return Optional.empty();
        }

        ActiveNetwork raw = parsed.get();
        String iface = raw.iface();
        String network = raw.network();
        int prefix = raw.prefix();
        String note = null;

        // Resolve IP via the injectable seam
        Optional<Inet4Address> ipOpt = ipResolver.apply(iface);
        String ipAddress = ipOpt.map(addr -> addr.getHostAddress()).orElse(null);

        // Clamp if wider than the scan-size cap
        if (prefix < ScanSizeGuard.MAX_ALLOWED_PREFIX) {
            int detectedPrefix = prefix;
            prefix = ScanSizeGuard.MAX_ALLOWED_PREFIX;
            // Recompute network anchored on the host IP
            if (ipAddress != null) {
                network = recomputeNetwork(ipAddress, prefix);
            }
            note = "Detected /" + detectedPrefix + " narrowed to /" + ScanSizeGuard.MAX_ALLOWED_PREFIX
                + " (scan size cap) — adjust if needed.";
        }

        String cidr = network + "/" + prefix;
        return Optional.of(new ActiveNetwork(iface, cidr, ipAddress, prefix, note));
    }

    // -------------------------------------------------------------------------
    // Pure parse — package-visible for unit testing without I/O
    // -------------------------------------------------------------------------

    /**
     * Parses a {@code /proc/net/route} fixture (list of lines, header first).
     * Returns a partial {@link ActiveNetwork} (no {@code ipAddress}, no clamp)
     * or empty if no default route is found.
     *
     * <p>The little-endian hex fields are reversed via {@link Integer#reverseBytes}
     * before dotted-quad formatting and {@link Integer#bitCount} for the prefix.
     *
     * <p>Columns (tab-separated):
     * {@code Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT}
     */
    static Optional<ActiveNetwork> parseRouteTable(List<String> lines) {
        String defaultIface = null;

        // First pass: find the interface carrying the default route
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            String[] fields = trimmed.split("\\s+");
            if (fields.length < 8) continue;
            // Skip header
            if ("Iface".equalsIgnoreCase(fields[0])) continue;

            String dest = fields[1].toUpperCase();
            String mask = fields[7].toUpperCase();
            String gw   = fields[2].toUpperCase();

            // Default route: Destination=0, Mask=0, Gateway≠0
            if (ALL_ZEROS_HEX.equals(dest) && ALL_ZEROS_HEX.equals(mask)
                    && !ALL_ZEROS_HEX.equals(gw)) {
                defaultIface = fields[0];
                break;
            }
        }

        if (defaultIface == null) {
            return Optional.empty();
        }

        // Second pass: find the on-link connected row for the default iface
        // (Gateway=0, Mask≠0, Mask≠FFFFFFFF)
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            String[] fields = trimmed.split("\\s+");
            if (fields.length < 8) continue;
            if ("Iface".equalsIgnoreCase(fields[0])) continue;

            String iface = fields[0];
            if (!defaultIface.equals(iface)) continue;

            String dest = fields[1].toUpperCase();
            String gw   = fields[2].toUpperCase();
            String mask = fields[7].toUpperCase();

            // On-link row: Gateway=0, non-zero non-host mask, non-zero destination
            if (ALL_ZEROS_HEX.equals(gw)
                    && !ALL_ZEROS_HEX.equals(mask)
                    && !ALL_ONES_HEX.equals(mask)
                    && !ALL_ZEROS_HEX.equals(dest)) {
                String network = hexLeToIp(dest);
                int prefix = Integer.bitCount(Integer.reverseBytes(
                    (int) Long.parseLong(mask, 16)));
                // Return partial ActiveNetwork (no IP, no cidr built yet, no note)
                return Optional.of(new ActiveNetwork(iface, network + "/" + prefix, null, prefix, null));
            }
        }

        return Optional.empty();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Converts a little-endian 8-hex-char field to a dotted-quad IPv4 string. */
    private static String hexLeToIp(String hexLe) {
        int le = (int) Long.parseLong(hexLe, 16);
        int be = Integer.reverseBytes(le);
        return ((be >>> 24) & 0xFF) + "."
             + ((be >>> 16) & 0xFF) + "."
             + ((be >>> 8)  & 0xFF) + "."
             + ( be         & 0xFF);
    }

    /** Returns {@code ip & mask(prefix)} as a dotted-quad string. */
    private static String recomputeNetwork(String hostIp, int prefix) {
        try {
            byte[] addr = java.net.InetAddress.getByName(hostIp).getAddress();
            int mask = (prefix == 0) ? 0 : (0xFFFFFFFF << (32 - prefix));
            int ip = ((addr[0] & 0xFF) << 24) | ((addr[1] & 0xFF) << 16)
                   | ((addr[2] & 0xFF) <<  8) |  (addr[3] & 0xFF);
            int network = ip & mask;
            return ((network >>> 24) & 0xFF) + "."
                 + ((network >>> 16) & 0xFF) + "."
                 + ((network >>>  8) & 0xFF) + "."
                 + ( network         & 0xFF);
        } catch (Exception e) {
            log.warn("Failed to recompute network for host {} prefix {}: {}", hostIp, prefix, e.getMessage());
            return hostIp;
        }
    }

    /**
     * Default IP resolver — wraps {@link NetworkInterface#getByName(String)}
     * filtered to the first {@link Inet4Address}. Returns empty on any exception.
     */
    private static Optional<Inet4Address> resolveIp(String ifaceName) {
        try {
            NetworkInterface nic = NetworkInterface.getByName(ifaceName);
            if (nic == null) return Optional.empty();
            for (InterfaceAddress addr : nic.getInterfaceAddresses()) {
                if (addr.getAddress() instanceof Inet4Address ipv4) {
                    return Optional.of(ipv4);
                }
            }
        } catch (SocketException e) {
            log.debug("Could not resolve IP for iface {}: {}", ifaceName, e.getMessage());
        }
        return Optional.empty();
    }

    // -------------------------------------------------------------------------
    // Carrier record
    // -------------------------------------------------------------------------

    /**
     * Carrier for the detected network. {@code cidr} is the fully-formed CIDR
     * string ({@code network + "/" + effectivePrefix}). {@code note} is non-null
     * only when the prefix was clamped. {@code ipAddress} may be null when the
     * IP resolver found no address for the interface.
     *
     * <p>The {@code network} field is extracted from {@code cidr} for the
     * {@link #parseRouteTable(List)} path where only the raw network is known
     * pre-clamp; callers that need only the pre-clamp network access it via
     * {@code cidr.substring(0, cidr.indexOf('/'))}.
     *
     * <p>Package-visible so the test can access the raw fields without going
     * through the full {@code detect()} pipeline.
     */
    public record ActiveNetwork(
        String iface,
        /** Fully-formed CIDR, e.g. {@code 192.168.68.0/22}. */
        String cidr,
        /** Host IP on the interface, null if the resolver returned empty. */
        String ipAddress,
        /** Effective prefix after any clamp. */
        int prefix,
        /** Non-null when the prefix was narrowed from the raw detected value. */
        String note
    ) {
        /**
         * Convenience accessor: the network address portion of {@link #cidr()},
         * without the prefix. E.g. {@code "192.168.68.0"}.
         */
        public String network() {
            int slash = cidr.indexOf('/');
            return slash >= 0 ? cidr.substring(0, slash) : cidr;
        }
    }
}
