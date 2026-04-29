package io.castellum.ot.bacnet;

/**
 * Builds read-only BACnet/IP PDU frames.
 *
 * <p>Service choices Castellum emits: {@link #SVC_WHO_IS} and {@link #SVC_READ_PROPERTY}.
 * The following write/control service choices are NEVER constructed:
 * 0x07 AtomicWriteFile, 0x0A CreateObject, 0x0B DeleteObject,
 * 0x0F WriteProperty, 0x10 WritePropertyMultiple,
 * 0x11 DeviceCommunicationControl, 0x12 ConfirmedPrivateTransfer,
 * 0x14 ReinitializeDevice.
 */
public final class BacnetFrames {

    /** BVLL header byte 0 — BACnet/IP. */
    public static final byte BVLL_TYPE_BIP = (byte) 0x81;

    /** BVLL function 0x0A — Original-Unicast-NPDU. */
    public static final byte BVLL_FN_UNICAST_NPDU = 0x0A;

    /** APDU type 0x10 — Unconfirmed-Request. */
    public static final byte APDU_TYPE_UNCONFIRMED = 0x10;

    /** APDU type 0x00 — Confirmed-Request. */
    public static final byte APDU_TYPE_CONFIRMED = 0x00;

    /** Service choice 0x08 — Who-Is (unconfirmed). */
    public static final byte SVC_WHO_IS = 0x08;

    /** Service choice 0x0C (decimal 12) — ReadProperty (confirmed). */
    public static final byte SVC_READ_PROPERTY = 0x0C;

    /** Property identifier: Vendor Name (121 decimal = 0x79). */
    public static final int PROP_VENDOR_NAME = 121;

    /** Property identifier: Model Name (70 decimal = 0x46). */
    public static final int PROP_MODEL_NAME = 70;

    /** Property identifier: Firmware Revision (44 decimal = 0x2C). */
    public static final int PROP_FIRMWARE_REVISION = 44;

    /** Property identifier: Application Software Version (12 decimal = 0x0C). */
    public static final int PROP_APPLICATION_SOFTWARE_VERSION = 12;

    private BacnetFrames() {}

    /**
     * Builds a unicast Who-Is frame.
     *
     * <p>Structure: BVLL(4) + NPDU(2) + APDU-Unconfirmed(1=type) + service(1=0x08)
     * = ~16 bytes (no low/high device-instance-range for global Who-Is).
     *
     * @return BVLL+NPDU+APDU bytes for unicast Who-Is
     */
    public static byte[] whoIsUnicast() {
        // APDU: type=Unconfirmed(0x10) | service=Who-Is(0x08)
        byte[] apdu = {APDU_TYPE_UNCONFIRMED, SVC_WHO_IS};
        return buildBvllNpduFrame(apdu);
    }

    /**
     * Builds a Confirmed-Request ReadProperty frame for the given device object id and property.
     *
     * <p>Structure: BVLL(4) + NPDU(2) + APDU-Confirmed(3=type+invoke+maxResp) + service + encoded-args.
     *
     * @param deviceObjectId BACnet device object identifier (device type=8, instance=deviceObjectId)
     * @param propertyId     BACnet property identifier
     * @param invokeId       confirmed-request invoke id (0–255, echoed in response)
     * @return BVLL+NPDU+APDU bytes
     */
    public static byte[] readProperty(int deviceObjectId, int propertyId, byte invokeId) {
        // APDU Confirmed-Request:
        // byte[0] = 0x00 (type=Confirmed, seg=N, max-segs=0, max-resp=5=1024)
        // byte[1] = invoke-id
        // byte[2] = service-choice = 0x0C (ReadProperty)
        // Context tag 0: objectIdentifier (device type=8, encoded as 32-bit value = type<<22|instance)
        // Context tag 1: propertyIdentifier
        long objId = ((long) 8 << 22) | (deviceObjectId & 0x3FFFFF);
        byte[] objIdEncoded = encodeContextTagUint(0, objId, 4);
        byte[] propIdEncoded = encodeContextTagUint(1, propertyId, computeUintLen(propertyId));

        byte[] apduHeader = {
            APDU_TYPE_CONFIRMED,           // type=Confirmed, max-segs=0, max-resp=5
            0x05,                          // max-response-segments=5 (1024 bytes)
            invokeId,                      // invoke ID
            SVC_READ_PROPERTY              // service choice 0x0C
        };

        byte[] apdu = concat(apduHeader, objIdEncoded, propIdEncoded);
        return buildBvllNpduFrame(apdu);
    }

    // ---- Private helpers ----

    private static byte[] buildBvllNpduFrame(byte[] apdu) {
        // NPDU: version=1, control=0 (no special routing)
        byte[] npdu = {0x01, 0x00};
        int totalLen = 4 + npdu.length + apdu.length; // BVLL(4) + NPDU + APDU
        byte[] frame = new byte[totalLen];
        frame[0] = BVLL_TYPE_BIP;
        frame[1] = BVLL_FN_UNICAST_NPDU;
        frame[2] = (byte) ((totalLen >> 8) & 0xFF);
        frame[3] = (byte) (totalLen & 0xFF);
        System.arraycopy(npdu, 0, frame, 4, npdu.length);
        System.arraycopy(apdu, 0, frame, 4 + npdu.length, apdu.length);
        return frame;
    }

    /**
     * Encodes a context-tagged unsigned integer in BACnet ASN.1 encoding.
     *
     * @param tag    context tag number (0–14)
     * @param value  unsigned value
     * @param lenHint number of bytes to encode the value in (1, 2, 3, or 4)
     */
    private static byte[] encodeContextTagUint(int tag, long value, int lenHint) {
        // Tag byte: context-specific | tag-number | length-hint
        // For tag 0-14: tag byte = (tag << 4) | 0x08 (context-specific) | len-hint
        // len-hint: 1=1byte, 2=2bytes, 3=3bytes, 4=4bytes
        byte tagByte = (byte) ((tag << 4) | 0x08 | lenHint);
        byte[] encoded = new byte[1 + lenHint];
        encoded[0] = tagByte;
        for (int i = lenHint - 1; i >= 0; i--) {
            encoded[1 + (lenHint - 1 - i)] = (byte) ((value >> (i * 8)) & 0xFF);
        }
        return encoded;
    }

    private static int computeUintLen(int value) {
        if (value <= 0xFF) return 1;
        if (value <= 0xFFFF) return 2;
        return 4;
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }
}
