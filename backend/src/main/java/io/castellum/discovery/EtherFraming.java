package io.castellum.discovery;

/**
 * Post-MAC Ethernet framing shared by the discovery decoders: the 2-byte discriminator
 * that follows the source MAC (an EtherType for {@link LldpDecoder}, an IEEE 802.3
 * length for {@link CdpDecoder}) and the offset where the MAC-plus-optional-tag header
 * ends, unwrapping at most one 802.1Q tag (TPID {@code 0x8100} — single-tag is the
 * contract; QinQ frames keep {@code 0x8100} as their discriminator and fail every
 * caller's test). Each decoder applies its own discriminator test to
 * {@link #typeOrLength()} and resumes parsing at {@link #payloadStart()}.
 */
record EtherFraming(int typeOrLength, int payloadStart) {

    private static final int ETHERTYPE_8021Q = 0x8100;

    /**
     * Reads the frame's post-source-MAC discriminator, skipping at most one 802.1Q tag:
     * an outer {@code 0x8100} re-reads the discriminator after the 4-byte tag (offset 16)
     * and shifts the payload start from 14 to 18. Returns null when the frame is too
     * short to hold the (possibly tagged) header.
     */
    static EtherFraming of(byte[] frame) {
        if (frame.length < 14) {
            return null;
        }
        int field12 = readU16(frame, 12);
        if (field12 != ETHERTYPE_8021Q) {
            return new EtherFraming(field12, 14);
        }
        if (frame.length < 18) {
            return null;
        }
        return new EtherFraming(readU16(frame, 16), 18);
    }

    private static int readU16(byte[] buf, int offset) {
        return ((buf[offset] & 0xFF) << 8) | (buf[offset + 1] & 0xFF);
    }
}
