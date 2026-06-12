package io.castellum.discovery;

import java.util.Locale;

/**
 * Deterministic synthetic IP key for MAC-only neighbors (no management address).
 *
 * <p>{@code forMac("AA:BB:CC:DD:EE:FF")} → {@code "mac:aa-bb-cc-dd-ee-ff"} — the same MAC
 * always maps to the same key, so the {@code UNIQUE(ip_address, origin_host_ip)} constraint
 * dedupes across sweeps.
 */
public final class PlaceholderIp {

    private static final String PREFIX = "mac:";

    private PlaceholderIp() {
    }

    public static String forMac(String mac) {
        return PREFIX + mac.trim().toLowerCase(Locale.ROOT).replace(':', '-');
    }

    public static boolean isPlaceholder(String ip) {
        return ip != null && ip.startsWith(PREFIX);
    }
}
