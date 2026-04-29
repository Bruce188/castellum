package io.castellum.ot.modbus;

/**
 * Builds Modbus/TCP read-only PDU frames.
 *
 * <p>Only read-classified function codes are ever constructed here:
 * <ul>
 *   <li>FC 0x2B (0x43) — Encapsulated Interface Transport with MEI 0x0E Read Device Identification</li>
 * </ul>
 *
 * <p>Forbidden write function codes (0x05, 0x06, 0x0F, 0x10, 0x16, 0x17) are never constructed.
 */
public final class ModbusFrames {

    /** Function code 0x2B — Encapsulated Interface Transport (Read Device Identification via MEI 0x0E). */
    public static final byte FN_ENCAP_INTERFACE = 0x2B;

    /** MEI type 0x0E — Read Device Identification. */
    public static final byte MEI_READ_DEVICE_ID = 0x0E;

    /** Read Device ID code 0x01 — basic (mandatory objects 0x00..0x02). */
    public static final byte READ_DEV_ID_BASIC = 0x01;

    /** Object id 0x00 — VendorName (mandatory object 0). */
    public static final byte OBJECT_ID_VENDOR = 0x00;

    /** Default unit id for Modbus/TCP server. */
    public static final byte DEFAULT_UNIT_ID = 0x01;

    private ModbusFrames() {}

    /**
     * Builds the 11-byte Read-Device-Identification request frame:
     * <pre>
     * [txn_hi, txn_lo, 0x00, 0x00, 0x00, 0x05, unitId, 0x2B, 0x0E, 0x01, 0x00]
     * </pre>
     * MBAP: transaction-id (2), protocol-id (2 = 0x0000), length (2 = 0x0005), unit-id (1).
     * PDU: function code 0x2B, MEI type 0x0E, Read Device ID code 0x01, object id 0x00.
     *
     * @param transactionId the MBAP transaction id (echoed in response).
     * @param unitId        Modbus slave id ({@link #DEFAULT_UNIT_ID} for most targets).
     * @return 11-byte frame ready to write to the Modbus/TCP socket.
     */
    public static byte[] readDeviceIdentificationRequest(short transactionId, byte unitId) {
        byte[] frame = new byte[11];
        // MBAP header
        frame[0] = (byte) ((transactionId >> 8) & 0xFF); // transaction id high
        frame[1] = (byte) (transactionId & 0xFF);        // transaction id low
        frame[2] = 0x00;                                  // protocol id high
        frame[3] = 0x00;                                  // protocol id low
        frame[4] = 0x00;                                  // length high
        frame[5] = 0x05;                                  // length low (unitId + 4 PDU bytes)
        frame[6] = unitId;                                 // unit id
        // PDU
        frame[7] = FN_ENCAP_INTERFACE;  // FC 0x2B
        frame[8] = MEI_READ_DEVICE_ID;  // MEI type 0x0E
        frame[9] = READ_DEV_ID_BASIC;   // Read Device ID code 0x01
        frame[10] = OBJECT_ID_VENDOR;   // Object id 0x00
        return frame;
    }
}
