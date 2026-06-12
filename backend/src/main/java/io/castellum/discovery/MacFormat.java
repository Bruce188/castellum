package io.castellum.discovery;

/**
 * Canonical wire-bytes → string MAC formatter for the discovery package.
 *
 * <p>Produces the lowercase colon-separated {@code %02x} form (e.g.
 * {@code "aa:bb:cc:dd:ee:ff"}) that matches the ARP-reader output, so MAC keys from
 * different sources collide correctly in {@link DeviceUpsertService}. Shared by
 * {@link LldpDecoder} and {@link CdpDecoder}.
 */
final class MacFormat {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private MacFormat() {
        throw new UnsupportedOperationException("static utility");
    }

    /** Formats the six wire bytes at {@code from} as lowercase colon-separated {@code %02x}. */
    static String format(byte[] buf, int from) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                sb.append(':');
            }
            int b = buf[from + i] & 0xFF;
            sb.append(HEX[b >>> 4]).append(HEX[b & 0x0F]);
        }
        return sb.toString();
    }
}
