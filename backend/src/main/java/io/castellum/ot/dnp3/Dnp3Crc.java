package io.castellum.ot.dnp3;

/**
 * CRC-16-DNP implementation per IEEE 1815-2012 Annex E.
 *
 * <p>Polynomial: 0x3D65 (reflected form 0xA6BC).
 * Initial value: 0x0000.
 * Final XOR: 0xFFFF.
 */
public final class Dnp3Crc {

    /** Pre-computed lookup table for CRC-16-DNP (reflected polynomial 0xA6BC). */
    private static final int[] TABLE = buildTable();

    private Dnp3Crc() {}

    private static int[] buildTable() {
        int[] table = new int[256];
        for (int i = 0; i < 256; i++) {
            int crc = i;
            for (int j = 0; j < 8; j++) {
                if ((crc & 1) != 0) {
                    crc = (crc >>> 1) ^ 0xA6BC;
                } else {
                    crc = crc >>> 1;
                }
            }
            table[i] = crc;
        }
        return table;
    }

    /**
     * Computes CRC-16-DNP over {@code data[offset..offset+length-1]}.
     *
     * @param data   source bytes
     * @param offset start position (inclusive)
     * @param length number of bytes to include
     * @return 16-bit CRC value (final XOR 0xFFFF applied)
     */
    public static int crc(byte[] data, int offset, int length) {
        int crc = 0x0000;
        for (int i = offset; i < offset + length; i++) {
            crc = (crc >>> 8) ^ TABLE[(crc ^ (data[i] & 0xFF)) & 0xFF];
        }
        return crc ^ 0xFFFF;
    }

    /**
     * Convenience overload: CRC over the whole array.
     *
     * @param data byte array
     * @return 16-bit CRC value
     */
    public static int crc(byte[] data) {
        return crc(data, 0, data.length);
    }
}
