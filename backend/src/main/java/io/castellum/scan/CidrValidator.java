package io.castellum.scan;

import java.util.regex.Pattern;

public final class CidrValidator {

    // RFC-4632-correct: each octet 0-255, prefix length 0-32.
    // Prefixes shorter than /8 are rejected to prevent "scan the internet" abuse.
    private static final Pattern CIDR = Pattern.compile(
        "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)/(3[0-2]|[12]?\\d)$"
    );

    // A single dotted-quad IPv4 host address with no prefix (each octet 0-255).
    private static final Pattern HOST = Pattern.compile(
        "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$"
    );

    /** Minimum prefix length permitted (inclusive). Rejects overly broad ranges like 0.0.0.0/0. */
    static final int MIN_PREFIX_LENGTH = 8;

    private CidrValidator() {}

    public static boolean isValid(String input) {
        if (input == null || !CIDR.matcher(input).matches()) {
            return false;
        }
        int prefix = Integer.parseInt(input.substring(input.lastIndexOf('/') + 1));
        return prefix >= MIN_PREFIX_LENGTH;
    }

    public static String requireValid(String input) {
        if (!isValid(input)) {
            throw new IllegalArgumentException("invalid CIDR");
        }
        return input;
    }

    /** True when {@code input} is a single, well-formed dotted-quad IPv4 host (no prefix). */
    public static boolean isValidHost(String input) {
        return input != null && HOST.matcher(input).matches();
    }

    /**
     * Validate a single IPv4 host address (no prefix). Used for the explicit alive-host target
     * list handed to nmap — every entry must be a literal address, never a CIDR, so a hostile or
     * malformed value cannot widen the scan or inject argv tokens.
     */
    public static String requireValidHost(String input) {
        if (!isValidHost(input)) {
            throw new IllegalArgumentException("invalid host address");
        }
        return input;
    }

    /**
     * True when the IPv4 host address {@code host} falls within the network described by
     * {@code cidr}. Pure 32-bit integer arithmetic (mirrors {@code ActiveNetworkDetector}'s
     * mask math); IPv6 and malformed inputs return {@code false}.
     */
    public static boolean cidrContainsHost(String cidr, String host) {
        if (cidr == null || host == null || !CIDR.matcher(cidr).matches() || !isValidHost(host)) {
            return false;
        }
        int slash = cidr.lastIndexOf('/');
        int prefix = Integer.parseInt(cidr.substring(slash + 1));
        Integer network = toInt(cidr.substring(0, slash));
        Integer addr = toInt(host);
        if (network == null || addr == null) {
            return false;
        }
        int mask = (prefix == 0) ? 0 : (0xFFFFFFFF << (32 - prefix));
        return (network & mask) == (addr & mask);
    }

    /** Parse a validated dotted-quad into a 32-bit int, or {@code null} on any malformation. */
    private static Integer toInt(String dottedQuad) {
        String[] parts = dottedQuad.split("\\.");
        if (parts.length != 4) {
            return null;
        }
        int value = 0;
        for (String part : parts) {
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                return null;
            }
            if (octet < 0 || octet > 255) {
                return null;
            }
            value = (value << 8) | octet;
        }
        return value;
    }
}
