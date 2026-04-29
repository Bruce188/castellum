package io.castellum.ot.modbus;

import io.castellum.ot.OtProbeDecodeException;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pure-function parser for Modbus/TCP Read-Device-Identification responses (FC 0x2B / MEI 0x0E).
 *
 * <p>Validates all length fields before access; throws {@link OtProbeDecodeException} on any
 * bounds violation, unexpected function/MEI code, or exception response.
 */
public final class ModbusDecoder {

    /** Maximum Modbus device-identification objects per response (spec § 6.21). */
    static final int MAX_OBJECTS = 7;

    private ModbusDecoder() {}

    /**
     * Decodes a Modbus/TCP Read-Device-Identification response.
     *
     * @param response full response frame including MBAP header (7 bytes) + PDU.
     * @return insertion-ordered map of objectId → ASCII string value (keys 0..6 per spec).
     * @throws OtProbeDecodeException on bounds violation, unexpected function code,
     *         exception response (function code 0xAB), or MEI type mismatch.
     */
    public static Map<Integer, String> decode(byte[] response) {
        // 1. Validate minimum length: MBAP (7) + function code (1) + at least 1 PDU byte
        if (response == null || response.length < 9) {
            throw new OtProbeDecodeException("truncated frame: length=" +
                (response == null ? 0 : response.length) + " (minimum 9)");
        }

        // 2. Read and validate MBAP length field (bytes 4–5, BE16)
        int mbapLength = ((response[4] & 0xFF) << 8) | (response[5] & 0xFF);
        // mbapLength = unitId (1) + PDU bytes remaining; so total bytes = 6 (MBAP minus length) + mbapLength
        if (6 + mbapLength > response.length) {
            throw new OtProbeDecodeException(
                "MBAP length field claims " + mbapLength + " bytes but frame has only " + response.length);
        }

        // 3. Validate function code at offset 7
        int fnCode = response[7] & 0xFF;
        if (fnCode == 0xAB) {
            throw new OtProbeDecodeException("modbus exception response");
        }
        if (fnCode != 0x2B) {
            throw new OtProbeDecodeException("unexpected function code: 0x" + Integer.toHexString(fnCode));
        }

        // 4. Validate MEI type at offset 8
        int meiType = response[8] & 0xFF;
        if (meiType != 0x0E) {
            throw new OtProbeDecodeException("unexpected MEI type: 0x" + Integer.toHexString(meiType));
        }

        // Minimum for the fixed header: through offset 12 (conformity, more, nextObj, numObjects)
        if (response.length < 13) {
            throw new OtProbeDecodeException("truncated frame: missing conformity/object-count header");
        }

        // 5. Parse conformity byte (9), more-follows (10), next-object-id (11), number-of-objects (12)
        // (offset 9 = conformity-level, offset 10 = more, offset 11 = nextObjectId, offset 12 = numObjects)
        int numberOfObjects = response[12] & 0xFF;
        if (numberOfObjects > MAX_OBJECTS) {
            throw new OtProbeDecodeException(
                "numberOfObjects=" + numberOfObjects + " exceeds maximum " + MAX_OBJECTS);
        }

        // 6. Iterate objects starting at offset 13
        int cursor = 13;
        Map<Integer, String> result = new LinkedHashMap<>();
        for (int i = 0; i < numberOfObjects; i++) {
            // Need at least 2 bytes for objectId + length
            if (cursor + 2 > response.length) {
                throw new OtProbeDecodeException(
                    "bounds violation reading object header at offset " + cursor);
            }
            int objectId = response[cursor] & 0xFF;
            int objectLen = response[cursor + 1] & 0xFF;
            cursor += 2;
            // Validate objectLen bytes are available
            if (cursor + objectLen > response.length) {
                throw new OtProbeDecodeException(
                    "object " + objectId + " length=" + objectLen +
                    " runs past end of buffer (cursor=" + cursor + ", buf=" + response.length + ")");
            }
            String value = new String(response, cursor, objectLen, StandardCharsets.US_ASCII);
            result.put(objectId, value);
            cursor += objectLen;
        }
        return result;
    }
}
