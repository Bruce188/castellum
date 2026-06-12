package io.castellum.discovery;

import org.springframework.stereotype.Service;

/**
 * Stateless first-match rule chain that buckets an IPv4 or IPv6 string into a
 * {@link DiscoveryScope}. Malformed input falls through to
 * {@link DiscoveryScope#PUBLIC} as a safe default.
 *
 * <p>IPv4 rule order (verbatim spec lines 318-326, plus RFC 6598):
 * <ol>
 *   <li>{@code 127.0.0.0/8} → {@link DiscoveryScope#LOOPBACK}</li>
 *   <li>{@code 169.254.0.0/16} → {@link DiscoveryScope#LINK_LOCAL}</li>
 *   <li>{@code 172.17.0.0/16} or {@code 172.18.0.0/16} →
 *       {@link DiscoveryScope#DOCKER_BRIDGE}</li>
 *   <li>{@code 192.168.0.0/16}, {@code 10.0.0.0/8}, {@code 172.16.0.0/12}
 *       (excluding the two Docker subnets above), {@code 100.64.0.0/10} →
 *       {@link DiscoveryScope#HOME}</li>
 *   <li>Everything else → {@link DiscoveryScope#PUBLIC}</li>
 * </ol>
 *
 * <p>IPv6 rule order:
 * <ol>
 *   <li>{@code ::1} → {@link DiscoveryScope#LOOPBACK}</li>
 *   <li>{@code fe80::/10} → {@link DiscoveryScope#LINK_LOCAL}</li>
 *   <li>{@code fc00::/7} (ULA = private LAN) → {@link DiscoveryScope#HOME}</li>
 *   <li>Everything else → {@link DiscoveryScope#PUBLIC}</li>
 * </ol>
 */
@Service
public class DiscoveryScopeClassifier {

    public DiscoveryScope classify(String ip) {
        if (ip == null || ip.isBlank()) return DiscoveryScope.PUBLIC;
        String s = ip.trim();
        // A colon means IPv6 — handled by its own prefix chain below.
        if (s.indexOf(':') >= 0) return classifyIpv6(s.toLowerCase());
        // Cheap shape check — anything else falls through.
        int dots = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == '.') dots++;
        if (dots != 3) return DiscoveryScope.PUBLIC;

        int[] octets = parseOctets(s);
        if (octets == null) return DiscoveryScope.PUBLIC;
        int a = octets[0], b = octets[1];

        if (a == 127) return DiscoveryScope.LOOPBACK;
        if (a == 169 && b == 254) return DiscoveryScope.LINK_LOCAL;
        if (a == 172 && (b == 17 || b == 18)) return DiscoveryScope.DOCKER_BRIDGE;
        if (a == 192 && b == 168) return DiscoveryScope.HOME;
        if (a == 10) return DiscoveryScope.HOME;
        if (a == 172 && b >= 16 && b <= 31) return DiscoveryScope.HOME;
        // RFC 6598 shared address space (CGNAT) — in practice Tailscale/ZeroTier
        // mesh peers on home networks, i.e. the operator's own devices.
        if (a == 100 && b >= 64 && b <= 127) return DiscoveryScope.HOME;
        return DiscoveryScope.PUBLIC;
    }

    /**
     * IPv6 bucketing by well-known prefix. Dependency-free string checks (no
     * {@code InetAddress} — this class is deliberately allocation-light);
     * {@code s} is already trimmed and lowercased.
     */
    private DiscoveryScope classifyIpv6(String s) {
        if (s.equals("::1")) return DiscoveryScope.LOOPBACK;
        int colon = s.indexOf(':');
        String hextet = s.substring(0, colon);
        // Both prefixes below have a full 4-hex-digit first hextet (no droppable
        // leading zeros), so shorter hextets cannot match.
        if (hextet.length() == 4) {
            // fe80::/10 — link-local (first hextet fe80-febf).
            if (hextet.startsWith("fe")) {
                char c = hextet.charAt(2);
                if (c == '8' || c == '9' || c == 'a' || c == 'b') return DiscoveryScope.LINK_LOCAL;
            }
            // fc00::/7 — unique local addresses (ULA = private LAN).
            if (hextet.startsWith("fc") || hextet.startsWith("fd")) return DiscoveryScope.HOME;
        }
        return DiscoveryScope.PUBLIC;
    }

    private int[] parseOctets(String s) {
        String[] parts = s.split("\\.");
        if (parts.length != 4) return null;
        int[] out = new int[4];
        for (int i = 0; i < 4; i++) {
            try {
                int v = Integer.parseInt(parts[i]);
                if (v < 0 || v > 255) return null;
                out[i] = v;
            } catch (NumberFormatException nfe) {
                return null;
            }
        }
        return out;
    }
}
