package io.castellum.discovery;

import io.castellum.domain.Device;
import org.springframework.stereotype.Service;

/**
 * Stateless, deterministic first-match rule chain that classifies a {@link Device}
 * into a {@link DeviceRole}.
 *
 * <p>Rule order (first match wins):
 * <ol>
 *   <li>Synthetic docker-net gateway: {@code source == DOCKER} AND hostname starts with
 *       {@code "docker-net:"} → {@link DeviceRole#UNKNOWN}. This rule MUST precede the
 *       CONTAINER and ROUTER rules so that synthetic gateway artifacts are never
 *       misclassified.</li>
 *   <li>Real Docker container: {@code source == DOCKER} (non-gateway) → {@link DeviceRole#CONTAINER}
 *       at {@link RoleConfidence#HIGH} (API-confirmed).</li>
 *   <li>Server OS fingerprint: {@code osName}/{@code osCpe} contains a server signal
 *       (case-insensitive) → {@link DeviceRole#SERVER} at HIGH.</li>
 *   <li>Desktop/client OS fingerprint: Windows client, macOS/Mac OS X, desktop Linux
 *       → {@link DeviceRole#DESKTOP} at HIGH. {@link DeviceRole#LAPTOP} is RESERVED — OS fingerprinting
 *       alone cannot distinguish laptop from desktop chassis; ambiguous desktop-class OSes
 *       deterministically map to {@link DeviceRole#DESKTOP}, never a non-deterministic guess.</li>
 *   <li>Gateway/last-octet-1 IP: IPv4 last octet == 1 → {@link DeviceRole#ROUTER} at HIGH.
 *       Weak signal only; ranks below OS and docker rules.</li>
 *   <li>Hostname substring tiebreaker (WEAK, last resort): obvious router/gateway hostname
 *       keywords may nudge {@link DeviceRole#ROUTER} at HIGH. Never the primary signal.</li>
 *   <li>macvlan/ipvlan heuristic (LOW confidence, MUST rank after all deterministic rules):
 *       when a non-DOCKER-sourced device has a MAC address whose OUI is the Docker-bridge
 *       locally-administered prefix {@code 02:42:*} AND corroborating behavioural signals
 *       (non-.1 last-octet IP, no router hostname) apply → {@link DeviceRole#CONTAINER} at
 *       {@link RoleConfidence#LOW}.
 *       <p><b>Residual false-positive risk:</b> any hardware or VM NIC vendor that chooses a
 *       locally-administered OUI (bit 1 of byte 0 set) and whose first two bytes happen to be
 *       {@code 02:42} would be misclassified. In practice only Docker bridge interfaces use
 *       this exact OUI, but the rule is a heuristic, not a guarantee. Operators should treat
 *       LOW-confidence CONTAINER roles as advisory and verify with the Docker API before acting.</li>
 *   <li>No signal → {@link DeviceRole#UNKNOWN} at HIGH (deterministic "no idea" result).</li>
 * </ol>
 *
 * <p>Null-safe: a {@code null} {@link Device}, or a device with all-null/blank signals,
 * returns {@link DeviceRole#UNKNOWN} at HIGH.
 */
@Service
public class DeviceRoleClassifier {

    /**
     * Classify the device and return both role and confidence.
     *
     * <p>All deterministic rules (1-6) return {@link RoleConfidence#HIGH}.
     * The macvlan heuristic (Rule 7) returns {@link RoleConfidence#LOW}.
     * The UNKNOWN fallthrough returns HIGH (deterministic "no signal" result).
     *
     * @param d the device to classify (null-safe)
     * @return role + confidence pair, never null
     */
    public RoleClassification classifyWithConfidence(Device d) {
        if (d == null) return new RoleClassification(DeviceRole.UNKNOWN, RoleConfidence.HIGH);

        // Rule 1: synthetic docker-net gateway (MUST be before CONTAINER and ROUTER rules)
        if (d.getDiscoverySource() == DiscoverySource.DOCKER
                && d.getHostname() != null
                && d.getHostname().startsWith("docker-net:")) {
            return new RoleClassification(DeviceRole.UNKNOWN, RoleConfidence.HIGH);
        }

        // Rule 2: real Docker container (API-confirmed → HIGH)
        if (d.getDiscoverySource() == DiscoverySource.DOCKER) {
            return new RoleClassification(DeviceRole.CONTAINER, RoleConfidence.HIGH);
        }

        // Rule 3: server OS fingerprint
        if (hasServerOs(d.getOsName()) || hasServerOs(d.getOsCpe())) {
            return new RoleClassification(DeviceRole.SERVER, RoleConfidence.HIGH);
        }

        // Rule 4: desktop/client OS fingerprint
        // LAPTOP is reserved — ambiguous desktop-class OSes → DESKTOP (deterministic, no guess)
        if (hasDesktopOs(d.getOsName()) || hasDesktopOs(d.getOsCpe())) {
            return new RoleClassification(DeviceRole.DESKTOP, RoleConfidence.HIGH);
        }

        // Rule 5: gateway by last-octet-1 IP (weak signal)
        if (lastOctetIsOne(d.getIpAddress())) {
            return new RoleClassification(DeviceRole.ROUTER, RoleConfidence.HIGH);
        }

        // Rule 6: hostname substring tiebreaker (WEAK — last resort)
        if (hasRouterHostname(d.getHostname())) {
            return new RoleClassification(DeviceRole.ROUTER, RoleConfidence.HIGH);
        }

        // Rule 7 (NEW): macvlan/ipvlan heuristic — LOW confidence, MUST rank after all
        // deterministic rules above so an API-confirmed or OS-fingerprinted device is never
        // demoted to a LOW guess. A non-DOCKER sweep host whose MAC OUI is the Docker-bridge
        // locally-administered prefix (02:42:*) with corroborating behavioural signals.
        if (isLikelyMacvlanContainer(d)) {
            return new RoleClassification(DeviceRole.CONTAINER, RoleConfidence.LOW);
        }

        // Rule 8: no signal → deterministic UNKNOWN
        return new RoleClassification(DeviceRole.UNKNOWN, RoleConfidence.HIGH);
    }

    /**
     * Classify the device and return only the role.
     *
     * <p>Delegates to {@link #classifyWithConfidence(Device)} — all F1 callers and tests
     * are byte-identical; this method is a stable API shim.
     *
     * @param d the device to classify (null-safe)
     * @return the classified role, never null
     */
    public DeviceRole classify(Device d) {
        return classifyWithConfidence(d).role();
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

    /**
     * Returns {@code true} when the device exhibits the macvlan/ipvlan container heuristic.
     *
     * <p>Primary signal: the MAC OUI is {@code 02:42:*} — the Docker-bridge locally-administered
     * OUI assigned to container veth interfaces by the Docker daemon. This OUI is NOT a
     * registered IEEE vendor prefix; Docker chose it precisely because locally-administered
     * OUIs are not assigned to physical hardware by manufacturers.
     *
     * <p>Corroborating signals (reduces false-positive rate):
     * <ul>
     *   <li>IP last octet is NOT 1 (gateway addresses are excluded by Rule 5 above, but
     *       this explicit check adds a belt-and-suspenders guard).</li>
     *   <li>Hostname does NOT match obvious router/gateway keywords (belt-and-suspenders
     *       against Rule 6 having already returned).</li>
     * </ul>
     *
     * <p><b>Residual false-positive risk:</b> any NIC whose first two octets happen to be
     * {@code 02:42} would be misclassified. In practice only Docker assigns this OUI, but
     * operators should treat a LOW-confidence CONTAINER role as advisory and verify.
     *
     * @param d device to test; caller guarantees non-null
     * @return true when all heuristic signals align
     */
    private static boolean isLikelyMacvlanContainer(Device d) {
        String mac = d.getMacAddress();
        if (mac == null || mac.isBlank()) return false;
        // OUI check: MAC must start with 02:42: (case-insensitive)
        if (!mac.toLowerCase(java.util.Locale.ROOT).startsWith("02:42:")) return false;
        // Corroborating: not a .1 gateway
        if (lastOctetIsOne(d.getIpAddress())) return false;
        // Corroborating: not a router by hostname
        if (hasRouterHostname(d.getHostname())) return false;
        return true;
    }

    /**
     * Returns {@code true} when the OS signal contains a server-leaning token.
     * Bare distro tokens ({@code centos}, {@code rhel}, {@code red hat}, {@code debian},
     * {@code freebsd}) are treated as SERVER signals by design — a desktop running one of
     * these distros maps to SERVER (precision tradeoff: determinism over chassis guessing).
     */
    private static boolean hasServerOs(String signal) {
        if (signal == null || signal.isBlank()) return false;
        String lower = signal.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("server")
            || lower.contains("windows_server")
            || lower.contains("centos")
            || lower.contains("rhel")
            || lower.contains("red hat")
            || lower.contains("debian")
            || lower.contains("freebsd");
    }

    private static boolean hasDesktopOs(String signal) {
        if (signal == null || signal.isBlank()) return false;
        String lower = signal.toLowerCase(java.util.Locale.ROOT);
        // macOS / Mac OS X
        if (lower.contains("mac os x") || lower.contains("macos")) return true;
        // Windows client — require "windows" but exclude the server variant
        if (lower.contains("windows") && !lower.contains("server") && !lower.contains("windows_server"))
            return true;
        // Desktop Linux (explicit desktop mention; Ubuntu server handled by hasServerOs)
        if (lower.contains("desktop") && !lower.contains("server")) return true;
        return false;
    }

    /** Returns {@code true} if the IPv4 last octet is exactly 1. */
    private static boolean lastOctetIsOne(String ip) {
        if (ip == null || ip.isBlank()) return false;
        int lastDot = ip.lastIndexOf('.');
        if (lastDot < 0 || lastDot >= ip.length() - 1) return false;
        String lastOctet = ip.substring(lastDot + 1).trim();
        try {
            return Integer.parseInt(lastOctet) == 1;
        } catch (NumberFormatException nfe) {
            return false;
        }
    }

    /** Weak hostname tiebreaker — only obvious router/gateway keywords. */
    private static boolean hasRouterHostname(String hostname) {
        if (hostname == null || hostname.isBlank()) return false;
        String lower = hostname.toLowerCase(java.util.Locale.ROOT);
        return lower.equals("router") || lower.equals("gateway") || lower.equals("gw")
            || lower.startsWith("router") || lower.startsWith("gateway");
    }
}
