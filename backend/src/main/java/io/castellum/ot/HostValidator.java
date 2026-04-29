package io.castellum.ot;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * Validates and parses IPv4 addresses for OT probe targets.
 *
 * <p>Rejects hostnames (closes DNS rebinding), IPv6, broadcast, multicast, and 0.0.0.0.
 * Allows loopback (127.0.0.0/8) for CI/test targets.
 */
public final class HostValidator {

    /** Matches IPv4 dotted-quad, octets 0–255. */
    private static final Pattern IPV4 = Pattern.compile(
        "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$"
    );

    private HostValidator() {}

    /**
     * Returns true iff input is a valid, allowed IPv4 dotted-quad.
     *
     * <p>Rejected: hostnames, IPv6 (colon), 0.0.0.0, 255.255.255.255 (broadcast),
     * and multicast addresses (first octet 224–239, Class D).
     */
    public static boolean isValid(String input) {
        if (input == null || !IPV4.matcher(input).matches()) {
            return false;
        }
        String[] parts = input.split("\\.");
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);
        int c = Integer.parseInt(parts[2]);
        int d = Integer.parseInt(parts[3]);
        // Reject 0.0.0.0
        if (a == 0 && b == 0 && c == 0 && d == 0) return false;
        // Reject broadcast 255.255.255.255
        if (a == 255 && b == 255 && c == 255 && d == 255) return false;
        // Reject multicast Class D (224.0.0.0–239.255.255.255)
        if (a >= 224 && a <= 239) return false;
        return true;
    }

    /**
     * Parses input into {@link InetAddress} via {@link InetAddress#getByAddress(byte[])} (no DNS).
     *
     * @param input IPv4 dotted-quad string
     * @return InetAddress constructed from raw bytes (no DNS resolution)
     * @throws IllegalArgumentException if input is invalid per {@link #isValid(String)}
     */
    public static InetAddress requireValid(String input) {
        if (!isValid(input)) {
            throw new IllegalArgumentException("Invalid or disallowed IPv4 address: " + input);
        }
        String[] parts = input.split("\\.");
        byte[] addr = new byte[]{
            (byte) Integer.parseInt(parts[0]),
            (byte) Integer.parseInt(parts[1]),
            (byte) Integer.parseInt(parts[2]),
            (byte) Integer.parseInt(parts[3])
        };
        try {
            return InetAddress.getByAddress(addr);
        } catch (UnknownHostException e) {
            // Cannot happen: getByAddress(byte[4]) only throws for wrong array length
            throw new IllegalArgumentException("Unexpected error constructing InetAddress", e);
        }
    }
}
