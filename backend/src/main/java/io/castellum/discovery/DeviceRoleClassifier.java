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
 *   <li>Real Docker container: {@code source == DOCKER} (non-gateway) → {@link DeviceRole#CONTAINER}.</li>
 *   <li>Server OS fingerprint: {@code osName}/{@code osCpe} contains a server signal
 *       (case-insensitive) → {@link DeviceRole#SERVER}.</li>
 *   <li>Desktop/client OS fingerprint: Windows client, macOS/Mac OS X, desktop Linux
 *       → {@link DeviceRole#DESKTOP}. {@link DeviceRole#LAPTOP} is RESERVED — OS fingerprinting
 *       alone cannot distinguish laptop from desktop chassis; ambiguous desktop-class OSes
 *       deterministically map to {@link DeviceRole#DESKTOP}, never a non-deterministic guess.</li>
 *   <li>Gateway/last-octet-1 IP: IPv4 last octet == 1 → {@link DeviceRole#ROUTER}. Weak
 *       signal only; ranks below OS and docker rules.</li>
 *   <li>Hostname substring tiebreaker (WEAK, last resort): obvious router/gateway hostname
 *       keywords may nudge {@link DeviceRole#ROUTER}. Never the primary signal.</li>
 *   <li>No signal → {@link DeviceRole#UNKNOWN}.</li>
 * </ol>
 *
 * <p>Null-safe: a {@code null} {@link Device}, or a device with all-null/blank signals,
 * returns {@link DeviceRole#UNKNOWN}.
 */
@Service
public class DeviceRoleClassifier {

    public DeviceRole classify(Device d) {
        if (d == null) return DeviceRole.UNKNOWN;

        // Rule 1: synthetic docker-net gateway (MUST be before CONTAINER and ROUTER rules)
        if (d.getDiscoverySource() == DiscoverySource.DOCKER
                && d.getHostname() != null
                && d.getHostname().startsWith("docker-net:")) {
            return DeviceRole.UNKNOWN;
        }

        // Rule 2: real Docker container
        if (d.getDiscoverySource() == DiscoverySource.DOCKER) {
            return DeviceRole.CONTAINER;
        }

        // Rule 3: server OS fingerprint
        if (hasServerOs(d.getOsName()) || hasServerOs(d.getOsCpe())) {
            return DeviceRole.SERVER;
        }

        // Rule 4: desktop/client OS fingerprint
        // LAPTOP is reserved — ambiguous desktop-class OSes → DESKTOP (deterministic, no guess)
        if (hasDesktopOs(d.getOsName()) || hasDesktopOs(d.getOsCpe())) {
            return DeviceRole.DESKTOP;
        }

        // Rule 5: gateway by last-octet-1 IP (weak signal)
        if (lastOctetIsOne(d.getIpAddress())) {
            return DeviceRole.ROUTER;
        }

        // Rule 6: hostname substring tiebreaker (WEAK — last resort)
        if (hasRouterHostname(d.getHostname())) {
            return DeviceRole.ROUTER;
        }

        // Rule 7: no signal
        return DeviceRole.UNKNOWN;
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

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
