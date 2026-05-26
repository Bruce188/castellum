package io.castellum.security;

import jakarta.servlet.http.HttpServletRequest;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * {@link ClientAddressResolver} that honours the {@code X-Forwarded-For} header
 * when the direct caller's IP is within a configured CIDR trust list.
 *
 * <p>When the proxy is trusted, the leftmost value in {@code X-Forwarded-For}
 * is returned as the effective client address. When the proxy is not trusted
 * (or the header is absent/empty), the resolver falls back to
 * {@link HttpServletRequest#getRemoteAddr()}.
 *
 * <p>Trust-list CIDRs are validated at construction time and any malformed
 * entry throws {@link IllegalArgumentException}.
 *
 * <p>Configured by:
 * <ul>
 *   <li>{@code castellum.security.rate-limit.client-address-strategy=xff}</li>
 *   <li>{@code castellum.security.rate-limit.trusted-proxies} — comma-separated CIDRs</li>
 * </ul>
 */
public class XForwardedForProvider implements ClientAddressResolver {

    /** Parsed (networkAddress, prefixLength) pairs. */
    private final List<long[]> trustedCidrs;

    /**
     * Constructs a resolver with the given trusted-proxy CIDR list.
     *
     * @param cidrs       list of CIDR strings (e.g. {@code "10.0.0.0/24"})
     * @param remoteAddr  unused — present only for symmetry with the test constructor pattern;
     *                    the actual remote address is resolved per-request
     * @throws IllegalArgumentException if any CIDR string is malformed
     */
    public XForwardedForProvider(List<String> cidrs, String remoteAddr) {
        this.trustedCidrs = parseCidrs(cidrs);
    }

    @Override
    public String resolve(HttpServletRequest request) {
        String remote = request.getRemoteAddr();
        if (!isTrusted(remote)) {
            return remote;
        }
        String xff = request.getHeader("X-Forwarded-For");
        if (xff == null || xff.isBlank()) {
            return remote;
        }
        String first = xff.split(",")[0].trim();
        return first.isEmpty() ? remote : first;
    }

    // ── CIDR helpers ──────────────────────────────────────────────────────────

    private boolean isTrusted(String ip) {
        if (ip == null) return false;
        long addr;
        try {
            addr = ipToLong(InetAddress.getByName(ip));
        } catch (UnknownHostException e) {
            return false;
        }
        for (long[] cidr : trustedCidrs) {
            long network = cidr[0];
            long mask = cidr[1];
            if ((addr & mask) == (network & mask)) {
                return true;
            }
        }
        return false;
    }

    private static List<long[]> parseCidrs(List<String> cidrs) {
        List<long[]> result = new ArrayList<>();
        for (String cidr : cidrs) {
            result.add(parseCidr(cidr));
        }
        return result;
    }

    /** Returns [networkAddress, mask] as IPv4 longs. Supports IPv4 CIDRs only. */
    private static long[] parseCidr(String cidr) {
        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid CIDR (expected <ip>/<prefix>): " + cidr);
        }
        int prefix;
        try {
            prefix = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid prefix length in CIDR: " + cidr, e);
        }
        if (prefix < 0 || prefix > 32) {
            throw new IllegalArgumentException("Prefix length must be 0-32 in CIDR: " + cidr);
        }
        InetAddress addr;
        try {
            addr = InetAddress.getByName(parts[0].trim());
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Unresolvable address in CIDR: " + cidr, e);
        }
        long network = ipToLong(addr);
        long mask = prefix == 0 ? 0L : (~0L << (32 - prefix)) & 0xFFFFFFFFL;
        return new long[]{network, mask};
    }

    private static long ipToLong(InetAddress addr) {
        byte[] raw = addr.getAddress();
        long result = 0;
        for (byte b : raw) {
            result = (result << 8) | (b & 0xFF);
        }
        return result;
    }
}
