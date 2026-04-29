package io.castellum.discovery;

import java.util.regex.Pattern;

/**
 * Validates Linux network interface names (IFNAMSIZ = 16 characters max).
 *
 * <p>Pattern: alphanumerics plus {@code _}, {@code :}, {@code .}, {@code -};
 * length 1–16 characters. Shell-injection characters (space, {@code ;},
 * {@code |}, {@code &}, backtick, {@code $}) are implicitly rejected by the
 * allowlist.
 */
public final class InterfaceNameValidator {

    /** Regex constant, also referenced by {@link PassiveDiscoveryRequest} @Pattern. */
    static final String IFACE_REGEX = "^[a-zA-Z0-9_:.-]{1,16}$";

    private static final Pattern IFACE_PATTERN = Pattern.compile(IFACE_REGEX);

    private InterfaceNameValidator() {}

    /**
     * Asserts that {@code iface} is a valid Linux interface name.
     *
     * @param iface interface name to validate
     * @throws IllegalArgumentException if null, empty, or does not match the allowed pattern
     */
    public static void requireValid(String iface) {
        if (iface == null || iface.isEmpty()) {
            throw new IllegalArgumentException("Interface name is null or empty");
        }
        if (!IFACE_PATTERN.matcher(iface).matches()) {
            throw new IllegalArgumentException("Invalid interface name: " + iface);
        }
    }
}
