package io.castellum.scan;

import java.util.regex.Pattern;

public final class CidrValidator {

    // RFC-4632-correct: each octet 0-255, prefix length 0-32.
    // Prefixes shorter than /8 are rejected to prevent "scan the internet" abuse.
    private static final Pattern CIDR = Pattern.compile(
        "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)/(3[0-2]|[12]?\\d)$"
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
}
