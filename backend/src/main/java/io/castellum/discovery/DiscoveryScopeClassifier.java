package io.castellum.discovery;

import org.springframework.stereotype.Service;

/**
 * Stateless first-match rule chain that buckets an IPv4 string into a
 * {@link DiscoveryScope}. IPv6 and malformed input fall through to
 * {@link DiscoveryScope#PUBLIC} as a safe default.
 *
 * <p>Rule order (verbatim spec lines 318-326):
 * <ol>
 *   <li>{@code 127.0.0.0/8} → {@link DiscoveryScope#LOOPBACK}</li>
 *   <li>{@code 169.254.0.0/16} → {@link DiscoveryScope#LINK_LOCAL}</li>
 *   <li>{@code 172.17.0.0/16} or {@code 172.18.0.0/16} →
 *       {@link DiscoveryScope#DOCKER_BRIDGE}</li>
 *   <li>{@code 192.168.0.0/16}, {@code 10.0.0.0/8}, {@code 172.16.0.0/12}
 *       (excluding the two Docker subnets above) →
 *       {@link DiscoveryScope#HOME}</li>
 *   <li>Everything else → {@link DiscoveryScope#PUBLIC}</li>
 * </ol>
 */
@Service
public class DiscoveryScopeClassifier {

    public DiscoveryScope classify(String ipv4) {
        if (ipv4 == null || ipv4.isBlank()) return DiscoveryScope.PUBLIC;
        String s = ipv4.trim();
        // Cheap shape check — IPv6 and anything else falls through.
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
