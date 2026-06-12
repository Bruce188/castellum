package io.castellum.discovery;

/**
 * Canonical wire-bytes → string MAC formatter for the discovery package.
 *
 * <p>Produces the lowercase colon-separated {@code %02x} form (e.g.
 * {@code "aa:bb:cc:dd:ee:ff"}) that matches the ARP-reader output, so MAC keys from
 * different sources collide correctly in {@link DeviceUpsertService}. Shared by
 * {@link LldpDecoder} (and the slice-6 CDP decoder).
 */
final class MacFormat {

    private MacFormat() {
        throw new UnsupportedOperationException("static utility");
    }

    /** Formats exactly six wire bytes as lowercase colon-separated {@code %02x}. */
    static String format(byte[] mac) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(String.format("%02x", mac[i] & 0xFF));
        }
        return sb.toString();
    }
}
