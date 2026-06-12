package io.castellum.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Parses the host's own connection table ({@code /proc/net/tcp}, {@code tcp6},
 * {@code udp}, {@code udp6}) and emits one {@link DiscoveredNeighbor} per unique
 * remote endpoint. TCP rows are kept only in state {@code 01} (ESTABLISHED); UDP
 * rows are kept when the remote address is non-zero (connected sockets).
 *
 * <p>Pure file read — no shell-out, no privileges, no wire traffic. This is the
 * source that makes internet peers visible on any host with outbound connections.
 *
 * <p>Loopback ({@code 127/8}, {@code ::1}), unspecified ({@code 0.0.0.0}, {@code ::})
 * and link-local ({@code fe80::/10}) remotes are skipped. The proc directory is
 * injectable for tests (mirror of {@link ActiveNetworkDetector}); missing files
 * (Windows/macOS, locked-down containers) degrade to an empty list — never an
 * exception.
 *
 * <p>Output is capped at {@code castellum.discovery.conn-table.max-remotes} distinct
 * remotes per read (first-N in file-read order, applied after dedupe) so a busy
 * public-facing host cannot grow the device inventory without bound — remote peers
 * choose to connect, so they would otherwise control the row count.
 */
@Service
public class ConnTableReader {

    private static final Logger log = LoggerFactory.getLogger(ConnTableReader.class);

    /** {@code st} column value for an ESTABLISHED TCP socket. */
    private static final String TCP_ESTABLISHED = "01";

    private final String procDir;
    private final int maxRemotes;

    public ConnTableReader(
            @Value("${castellum.discovery.conn-table.proc-dir:/proc/net}") String procDir,
            @Value("${castellum.discovery.conn-table.max-remotes:512}") int maxRemotes) {
        this.procDir = procDir;
        // A non-positive cap would silence the source entirely (or re-open the
        // unbounded path); clamp to at least one neighbor.
        this.maxRemotes = Math.max(1, maxRemotes);
    }

    /**
     * Reads all four proc tables and returns the deduplicated remote endpoints,
     * truncated to the configured ceiling. Returns an empty list when no table is
     * readable (non-Linux hosts).
     */
    public List<DiscoveredNeighbor> read() {
        Set<String> remoteIps = new LinkedHashSet<>();
        collect(Path.of(procDir, "tcp"), true, remoteIps);
        collect(Path.of(procDir, "tcp6"), true, remoteIps);
        collect(Path.of(procDir, "udp"), false, remoteIps);
        collect(Path.of(procDir, "udp6"), false, remoteIps);

        int dropped = remoteIps.size() - maxRemotes;
        if (dropped > 0) {
            log.warn("Connection tables yielded {} distinct remotes; keeping the first {} and "
                    + "dropping {} (castellum.discovery.conn-table.max-remotes)",
                remoteIps.size(), maxRemotes, dropped);
        }

        List<DiscoveredNeighbor> results = new ArrayList<>(Math.min(remoteIps.size(), maxRemotes));
        for (String ip : remoteIps) {
            if (results.size() == maxRemotes) {
                break;
            }
            results.add(new DiscoveredNeighbor(ip, null, null, null, null, null));
        }
        return results;
    }

    /**
     * Parses one proc table into {@code out}. {@code requireEstablished} applies the
     * TCP state filter; UDP tables instead rely on the non-zero-remote (unspecified)
     * check inside {@link #parseRemoteIp(String)}.
     */
    private void collect(Path table, boolean requireEstablished, Set<String> out) {
        if (!Files.exists(table)) {
            log.debug("Connection table not found at {}; skipping", table);
            return;
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(table, StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.debug("Failed to read connection table {}: {}", table, e.getMessage());
            return;
        }

        boolean headerSkipped = false;
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            if (!headerSkipped) {
                headerSkipped = true;
                continue;
            }

            // Columns: sl local_address rem_address st tx_queue:rx_queue ...
            String[] fields = trimmed.split("\\s+");
            if (fields.length < 4) {
                log.debug("Skipping malformed connection-table line (expected 4+ fields): {}", trimmed);
                continue;
            }
            if (requireEstablished && !TCP_ESTABLISHED.equals(fields[3])) {
                continue;
            }

            String ip = parseRemoteIp(fields[2]);
            if (ip != null) {
                out.add(ip);
            }
        }
    }

    /**
     * Decodes a {@code rem_address} field ({@code <hex-addr>:<hex-port>}) into an IP
     * string, or null when the remote is malformed, loopback, unspecified, or link-local.
     *
     * <p>Kernel format: IPv4 is 8 hex chars as one little-endian 32-bit word; IPv6 is
     * 32 hex chars as four little-endian 32-bit words.
     */
    private String parseRemoteIp(String remAddress) {
        int colon = remAddress.lastIndexOf(':');
        if (colon < 0) {
            log.debug("Skipping connection-table remote without port separator: {}", remAddress);
            return null;
        }
        String hex = remAddress.substring(0, colon);

        InetAddress addr;
        try {
            addr = decodeHexAddress(hex);
        } catch (NumberFormatException | UnknownHostException e) {
            log.debug("Skipping unparseable connection-table remote '{}': {}", remAddress, e.getMessage());
            return null;
        }
        if (addr == null) {
            log.debug("Skipping connection-table remote with unexpected length: {}", remAddress);
            return null;
        }

        // Self/non-routable remotes are noise, not neighbors.
        if (addr.isLoopbackAddress() || addr.isAnyLocalAddress() || addr.isLinkLocalAddress()) {
            return null;
        }
        return addr.getHostAddress();
    }

    /**
     * Converts the kernel's little-endian hex encoding to an {@link InetAddress}.
     * Returns null when the field is neither 8 (IPv4) nor 32 (IPv6) hex chars.
     */
    private static InetAddress decodeHexAddress(String hex) throws UnknownHostException {
        if (hex.length() == 8) {
            int be = Integer.reverseBytes((int) Long.parseLong(hex, 16));
            return InetAddress.getByAddress(new byte[] {
                (byte) (be >>> 24), (byte) (be >>> 16), (byte) (be >>> 8), (byte) be
            });
        }
        if (hex.length() == 32) {
            byte[] bytes = new byte[16];
            for (int group = 0; group < 4; group++) {
                int word = Integer.reverseBytes(
                    (int) Long.parseLong(hex.substring(group * 8, group * 8 + 8), 16));
                bytes[group * 4]     = (byte) (word >>> 24);
                bytes[group * 4 + 1] = (byte) (word >>> 16);
                bytes[group * 4 + 2] = (byte) (word >>> 8);
                bytes[group * 4 + 3] = (byte) word;
            }
            return InetAddress.getByAddress(bytes);
        }
        return null;
    }
}
